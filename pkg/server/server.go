package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"ohrenpirat.de/container-scanning/pkg/utils"
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
	imageScanner         ImageScanner
}

type ImageScanner func(ctx context.Context, name string, reference string) (report []byte, err error)

func CreateNewServer(
	configurationBaseKey string,
	upstreamUrl string,
	imageScanner ImageScanner,
) Server {
	return &registryProxyServer{
		configurationBaseKey: configurationBaseKey,
		upstreamUrl:          upstreamUrl,
		imageScanner:         imageScanner,
	}
}

func (regServ *registryProxyServer) Run(address string) error {
	log.Printf("registryProxyServer for entrypoint %s on %s...\n", regServ.configurationBaseKey, address)
	return http.ListenAndServe(address, utils.LogMiddlewareHandler(regServ, log.Printf))
}

func (regServ *registryProxyServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	manifestPattern := fmt.Sprintf("\\/v2\\/(%s)\\/manifests\\/(%s)", NameExpression, ReferenceExpression)
	blobsPattern := fmt.Sprintf("\\/v2\\/(%s)\\/blobs\\/(%s)", NameExpression, ReferenceExpression)
	if match, matches := utils.MatchPattern(request, manifestPattern); match && utils.MatchMethod(request, "GET", "HEAD") {
		name := matches[1]
		reference := matches[7]
		regServ.serveV2ManifestsRequest(writer, request, name, reference)
	} else if match, matches := utils.MatchPattern(request, blobsPattern); match && utils.MatchMethod(request, "GET", "HEAD") {
		name := matches[1]
		reference := matches[7]
		regServ.serveV2BlobsRequest(writer, request, name, reference)
	} else {
		regServ.serveProxy(writer, request)
	}
}

func (regServ *registryProxyServer) serveV2ManifestsRequest(writer http.ResponseWriter, request *http.Request, name string, reference string) {
	report, err := regServ.imageScanner(request.Context(), name, reference)
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
		regServ.serveProxy(writer, request)
	}
}

func (regServ *registryProxyServer) serveV2BlobsRequest(writer http.ResponseWriter, request *http.Request, name string, reference string) {
	regServ.serveProxy(writer, request)
}

func (regServ *registryProxyServer) serveProxy(writer http.ResponseWriter, request *http.Request) {
	upstreamRequest, err := utils.CloneRequest(regServ.upstreamUrl, request)
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
	utils.SendResponse(writer, upstreamResponse)
}
