package main

import (
	"log"
	"net/http"
	"ohrenpirat.de/container-scanning/pkg/utils"
)

type server struct {
	upstreamUrl string
}

func (serv *server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	utils.ProxyRequestTo(serv.upstreamUrl, writer, request)
}

func (serv *server) Run(address string) error {
	return http.ListenAndServe(address, utils.LogMiddlewareHandler(serv, log.Printf))
}

func main() {
	serv := server{upstreamUrl: "https://registry.ohrenpirat.de:5000"}
	serv.Run(":5555")
}
