package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"ohrenpirat.de/container-scanning/pkg/utils"
)

const (
	NameExpression      = "[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*(\\/[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*)*"
	ReferenceExpression = "([a-zA-Z0-9_][a-zA-Z0-9:._-]{0,127})"
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
	return http.ListenAndServe(address, utils.Trace(utils.LogMiddlewareHandler(regServ, log.Printf)))
}

func (regServ *registryProxyServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	manifestPattern := fmt.Sprintf("\\/v2\\/(%s)\\/manifests\\/(%s)", NameExpression, ReferenceExpression)
	blobsPattern := fmt.Sprintf("\\/v2\\/(%s)\\/blobs\\/(%s)", NameExpression, ReferenceExpression)

	if match, matches := utils.MatchPattern(request, manifestPattern); match && utils.MatchMethod(request, "GET") {
		name := matches[1]
		reference := matches[7]
		regServ.serveV2ManifestsRequest(writer, request, name, reference)
	} else if match, matches := utils.MatchPattern(request, blobsPattern); match && utils.MatchMethod(request, "GET") {
		name := matches[1]
		reference := matches[7]
		regServ.serveV2BlobsRequest(writer, request, name, reference)
	} else {
		regServ.serveProxy(writer, request)
	}
}

func CheckPolicy(report Report) bool {
	count := 0
	for _, reportResult := range report.Results {
		for _, vulnerability := range reportResult.Vulnerabilities {
			if vulnerability.Severity == "HIGH" || vulnerability.Severity == "CRITICAL" {
				count = count + 1
			}
		}
	}
	return count <= 0
}

type Report struct {
	Metadata ReportMetadata `json:"Metadata"`
	Results  []ReportResult `json:"Results"`
}

type ReportResult struct {
	Target          string                `json:"Target"`
	Vulnerabilities []ReportVulnerability `json:"Vulnerabilities"`
}

type ReportVulnerability struct {
	Severity         string              `json:"Severity"`
	VulnerabilityID  string              `json:"VulnerabilityID"`
	PkgIdentifier    ReportPkgIdentifier `json:"PkgIdentifier"`
	PublishedDate    string              `json:"PublishedDate"`
	LastModifiedDate string              `json:"LastModifiedDate"`
}

type ReportPkgIdentifier struct {
	PkgUrl string `json:"PURL"`
}

type ReportMetadata struct {
	ImageID string `json:"ImageID"`
}

type Manifest struct {
	MediaType string         `json:"mediaType"`
	Config    ManifestItem   `json:"config"`
	Layers    []ManifestItem `json:"layers"`
}

type ManifestItem struct {
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
	Digest    string `json:"digest"`
}

func (regServ *registryProxyServer) serveV2ManifestsRequest(writer http.ResponseWriter, request *http.Request, name string, reference string) {

	response, err := utils.SendProxyRequest(regServ.upstreamUrl, request)

	if err != nil {
		log.Printf("ERROR: unable fetch manifest  %s/%s:%s (%s)", regServ.upstreamUrl, name, reference, err.Error())
		http.Error(writer, "unable fetch manifest", http.StatusInternalServerError)
		return
	}

	if response.StatusCode != http.StatusOK {
		log.Printf("ERROR: got unexpected status %d for image Name %s:%s",
			response.StatusCode,
			name,
			reference,
		)
		utils.SendResponse(writer, response)
		return
	}

	if response.Header.Get("Content-Type") != "application/vnd.docker.distribution.manifest.v2+json" {
		log.Printf("ERROR: unexpected Content Type Header of manifest response of %s:%s, (%s)",
			name, reference,
			response.Header.Get("Content-Type"))
		http.Error(writer, "unexpected Content Type Header of manifest ", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("ERROR: unable to read response body from manifest  %s:%s (%s)", name, reference, err.Error())
		http.Error(writer, "unable to read response body from manifest", http.StatusInternalServerError)
		return
	}
	// und hier muss der Respone-Body wieder "zurückgesetzt" werden.
	response.Body = io.NopCloser(bytes.NewReader(body))

	var manifest Manifest
	err = json.Unmarshal(body, &manifest)
	if err != nil {
		log.Printf("ERROR: unable to unmarshal manifest file \n%s\n", string(body))
		http.Error(writer, "unable to unmarshal manifest", http.StatusInternalServerError)
		return
	}

	reportData, err := regServ.imageScanner(request.Context(), name, reference)
	if err != nil {
		log.Printf("[%s] ERROR: unable to scan image %s:%s (%s)", request.Context().Value("trace-id"), name, reference, err.Error())
		http.Error(writer, "unable to scan Image", http.StatusInternalServerError)
		return
	}

	var report Report
	err = json.Unmarshal(reportData, &report)
	if err != nil {
		log.Printf("ERROR: unable to unmarshal trivy report (%s) \n%s\n", err.Error(), string(reportData))
		http.Error(writer, "unable to unmarshal trivy report ", http.StatusInternalServerError)
		return
	}

	if report.Metadata.ImageID != manifest.Config.Digest {
		log.Printf("ERROR: illegal image ID unmatch (Manifest: %s. Report %s)", report.Metadata.ImageID, manifest.Config.Digest)
		http.Error(writer, "illegal image ID unmatch", http.StatusInternalServerError)
		return
	}

	if !CheckPolicy(report) {
		http.Error(writer,
			fmt.Sprintf(`

WARNING: Download of image %s:%s is prohibited due to existing vulnerabilities!!!
		 
		 Information about the containing vulnerabilities are shown below.

===================================================================================='
 %s
====================================================================================`, name, reference, string(reportData)),
			http.StatusForbidden)
		return
	} else {
		utils.SendResponse(writer, response)
	}
}

func (regServ *registryProxyServer) serveV2BlobsRequest(writer http.ResponseWriter, request *http.Request, name string, reference string) {
	regServ.serveProxy(writer, request)
}

func (regServ *registryProxyServer) serveProxy(writer http.ResponseWriter, request *http.Request) {
	utils.ProxyRequestTo(regServ.upstreamUrl, writer, request)
}
