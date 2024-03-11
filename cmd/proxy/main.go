package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"ohrenpirat.de/container-scanning/pkg/trivy"
	"ohrenpirat.de/container-scanning/pkg/utils"
	"regexp"
)

var upstreamServerURL = "https://registry.ohrenpirat.de:5000"

const (
	NameExpression      = "[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*(\\/[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*)*"
	ReferenceExpression = "[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}"
)

func main() {
	http.Handle("/",
		utils.LogRequestMiddleware(
			utils.LogMiddleware(dispatchHandler, log.Printf),
			log.Printf))

	port := 5000
	log.Printf("Proxy server listening on :%d...\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func dispatchHandler(w http.ResponseWriter, request *http.Request) {

	manifestPattern := fmt.Sprintf("\\/v2\\/(%s)\\/manifests\\/(%s)", NameExpression, ReferenceExpression)

	if !(request.Method == "GET" || request.Method == "HEAD") {
		http.Error(w, "use GET or HEAD", http.StatusMethodNotAllowed)
		return
	}

	regex := regexp.MustCompile(manifestPattern)

	if matches := regex.FindStringSubmatch(request.URL.Path); len(matches) > 0 {
		name := matches[1]
		reference := matches[7]
		log.Printf("GET /v2/..../manifests/... ==> %s", request.URL.Path)
		log.Printf("Name: %s, Refernece: %s", matches[1], matches[7])
		report, err := trivy.ScanDefault(request.Context(), name, reference)
		if err != nil {
			fmt.Printf("ERROR: unable to scan image %s:%s (%s)", name, reference, err.Error())
			http.Error(w, "unable to scan Image", http.StatusInternalServerError)
			return
		} else if len(report) > 0 {
			http.Error(w,
				fmt.Sprintf("\n\nDownload of image %s:%s is prohibited due to vulnerabilities. \n\n %s", name, reference, string(report)),
				http.StatusForbidden)
			return
		} else {
			proxyHandler(w, request)
		}
	} else {
		proxyHandler(w, request)
	}
}

func proxyHandler(w http.ResponseWriter, request *http.Request) {
	//utils.LogRequest(request, log.Printf)
	upstreamRequest, err := cloneRequest(upstreamServerURL, request)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	proxyClient := &http.Client{}
	upstreamResponse, err := proxyClient.Do(upstreamRequest)
	if err != nil {
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		return
	}
	defer upstreamResponse.Body.Close()

	//utils.LogResponse(upstreamResponse, log.Printf)
	sendResponse(w, upstreamResponse)
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
