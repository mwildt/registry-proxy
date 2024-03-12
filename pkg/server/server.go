package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"ohrenpirat.de/container-scanning/pkg/utils"
	"regexp"
)

const (
	NameExpression      = "[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*(\\/[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*)*"
	ReferenceExpression = "[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}"
)

type Server interface {
	http.Handler
	Run(address string) error
}

type registryProxyServer struct {
	configurationBaseKey string
	upstreamUrl          string
	handler              http.HandlerFunc
}

func (d registryProxyServer) Run(address string) error {
	log.Printf("registryProxyServer for entrypoint %s on %s...\n", d.configurationBaseKey, address)
	return http.ListenAndServe(address, d)
}

type ImageScanner func(ctx context.Context, name string, reference string) (report []byte, err error)

func CreateNewServer(
	configurationBaseKey string,
	upstreamUrl string,
	imageScanner ImageScanner,
) Server {
	handler := utils.LogMiddleware(dispatchHandler(imageScanner, upstreamUrl), log.Printf)

	return &registryProxyServer{
		configurationBaseKey: configurationBaseKey,
		upstreamUrl:          upstreamUrl,
		handler:              handler,
	}
}

func (d registryProxyServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	d.handler(writer, request)
}

func dispatchHandler(imageScanner ImageScanner, upstreamUrl string) http.HandlerFunc {

	return func(writer http.ResponseWriter, request *http.Request) {
		manifestPattern := fmt.Sprintf("\\/v2\\/(%s)\\/manifests\\/(%s)", NameExpression, ReferenceExpression)
		if !(request.Method == "GET" || request.Method == "HEAD") {
			http.Error(writer, "use GET or HEAD", http.StatusMethodNotAllowed)
			return
		}

		proxyHandler := proxyHandler(upstreamUrl)

		regex := regexp.MustCompile(manifestPattern)
		if matches := regex.FindStringSubmatch(request.URL.Path); len(matches) > 0 {
			name := matches[1]
			reference := matches[7]
			log.Printf("GET /v2/..../manifests/... ==> %s", request.URL.Path)
			log.Printf("Name: %s, Refernece: %s", matches[1], matches[7])
			report, err := imageScanner(request.Context(), name, reference)
			if err != nil {
				log.Printf("ERROR: unable to scan image %s:%s (%s)", name, reference, err.Error())
				http.Error(writer, "unable to scan Image", http.StatusInternalServerError)
				return
			} else if len(report) > 0 {
				http.Error(writer,
					fmt.Sprintf("\n\nDownload of image %s:%s is prohibited due to vulnerabilities. \n\n %s", name, reference, string(report)),
					http.StatusForbidden)
				return
			} else {
				proxyHandler(writer, request)
			}
		} else {
			proxyHandler(writer, request)
		}
	}

}

func proxyHandler(upstreamUrl string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {

		//utils.LogRequest(request, log.Printf)
		upstreamRequest, err := cloneRequest(upstreamUrl, request)
		if err != nil {
			http.Error(writer, "Failed to create proxy request", http.StatusInternalServerError)
			return
		}
		proxyClient := &http.Client{}
		upstreamResponse, err := proxyClient.Do(upstreamRequest)
		if err != nil {
			http.Error(writer, "Failed to proxy request", http.StatusBadGateway)
			return
		}
		defer upstreamResponse.Body.Close()

		//utils.LogResponse(upstreamResponse, log.Printf)
		sendResponse(writer, upstreamResponse)
	}
}

func sendResponse(w http.ResponseWriter, proxyRes *http.Response) {
	for key, values := range proxyRes.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(proxyRes.StatusCode)
	io.Copy(w, proxyRes.Body)
}

func cloneRequest(upstreamServiceUrl string, originalRequest *http.Request) (request *http.Request, err error) {
	proxyReq, err := http.NewRequest(
		originalRequest.Method,
		upstreamServiceUrl+originalRequest.URL.String(),
		originalRequest.Body)

	if err != nil {
		return request, err
	}
	proxyReq.Header = originalRequest.Header
	return proxyReq, err
}
