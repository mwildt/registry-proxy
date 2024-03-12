package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
)

type PrintFormatter func(format string, v ...any)

func LogMiddleware(next http.HandlerFunc, printFormatter PrintFormatter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		printFormatter("[%s] << %s::%s\n", r.Context().Value("trace-id"), r.Method, r.URL.Path)
		for header, values := range w.Header() {
			printFormatter("[%s] Request-Header %s: %s\n", r.Context().Value("trace-id"), header, strings.Join(values, ", "))
		}
		ww := NewStatusLoggingResponseWrapper(w)
		next(ww, r)
		printFormatter("[%s] >> %s::%s::%d\n", r.Context().Value("trace-id"), r.Method, r.URL.Path, ww.status)

	}
}

type funcWrapHandler struct {
	handlerFunc http.HandlerFunc
}

func (f funcWrapHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	f.handlerFunc(writer, request)
}

func Handler(handlerFunc http.HandlerFunc) http.Handler {
	return &funcWrapHandler{handlerFunc}
}

func LogMiddlewareHandler(next http.Handler, printFormatter PrintFormatter) http.Handler {
	return http.Handler(LogMiddleware(next.ServeHTTP, printFormatter))
}

func Trace(next http.Handler) http.Handler {
	return Handler(func(writer http.ResponseWriter, request *http.Request) {
		randomBytes := make([]byte, 8)
		_, _ = rand.Read(randomBytes)

		tracedContext := context.WithValue(request.Context(), "trace-id", base64.StdEncoding.EncodeToString(randomBytes))
		next.ServeHTTP(writer, request.WithContext(tracedContext))
	})
}

type StatusLoggingResponseWrapper struct {
	http.ResponseWriter
	status int
}

func NewStatusLoggingResponseWrapper(w http.ResponseWriter) *StatusLoggingResponseWrapper {
	return &StatusLoggingResponseWrapper{w, http.StatusOK}
}

func (lrw *StatusLoggingResponseWrapper) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

func LogRequestMiddleware(next http.HandlerFunc, printFormatter PrintFormatter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		LogRequest(r, printFormatter)
		next(w, r)
	}
}

func LogRequest(r *http.Request, printFormatter PrintFormatter) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		printFormatter("Failed to dump request: %v\n", err)
		return
	}
	printFormatter("Request:\n%s\n", requestDump)
}

func LogResponse(res *http.Response, printFormatter PrintFormatter) {
	responseDump, err := httputil.DumpResponse(res, true)
	if err != nil {
		printFormatter("Failed to dump response: %v\n", err)
		return
	}
	printFormatter("Upstream Response:\n%s\n", responseDump)
}

func MatchMethod(request *http.Request, methods ...string) bool {
	for _, method := range methods {
		if method == request.Method {
			return true
		}
	}
	return false
}

func MatchPattern(request *http.Request, pattern string) (match bool, matches []string) {
	regex := regexp.MustCompile(pattern)
	if matches := regex.FindStringSubmatch(request.URL.Path); len(matches) > 0 {
		return true, matches
	}
	return false, matches
}

func SendResponseWrapper(w http.ResponseWriter, proxyRes *ResponseWrapper) {

	for key, values := range proxyRes.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(proxyRes.StatusCode)
	io.Copy(w, proxyRes.Body)
}

func SendResponse(w http.ResponseWriter, proxyRes *http.Response) {
	for key, values := range proxyRes.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(proxyRes.StatusCode)
	io.Copy(w, proxyRes.Body)
}

func CloneRequest(upstreamServiceUrl string, originalRequest *http.Request) (request *http.Request, err error) {
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

func SendProxyRequest(upstreamUrl string, originalRequest *http.Request) (response *http.Response, err error) {
	upstreamRequest, err := CloneRequest(upstreamUrl, originalRequest)
	if err != nil {
		return response, err
	}
	proxyClient := &http.Client{}
	return proxyClient.Do(upstreamRequest)
}

func ProxyRequestTo(upstreamUrl string, writer http.ResponseWriter, originalRequest *http.Request) {
	upstreamRequest, err := CloneRequest(upstreamUrl, originalRequest)
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
	SendResponse(writer, upstreamResponse)
}

type ResponseWrapper struct {
	*http.Response
	bodyBuffer *bytes.Buffer
}

func NewResponseWrapper(resp *http.Response) (*ResponseWrapper, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyBuffer := bytes.NewBuffer(body)
	resp.Body = io.NopCloser(bodyBuffer) // Ersetzt den Response-Body mit dem Puffer

	return &ResponseWrapper{
		Response:   resp,
		bodyBuffer: bodyBuffer,
	}, nil
}

func (rw *ResponseWrapper) GetBody() []byte {
	return rw.bodyBuffer.Bytes()
}
