package utils

import (
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
)

type PrintFormatter func(format string, v ...any)

func LogMiddleware(next http.HandlerFunc, printFormatter PrintFormatter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ww := NewStatusLoggingResponseWrapper(w)
		next(ww, r)
		printFormatter("%s::%s::%d\n", r.Method, r.URL.Path, ww.status)
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
	return http.Handler(next)
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
