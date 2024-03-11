package utils

import (
	"net/http"
	"net/http/httputil"
)

type PrintFormatter func(format string, v ...any)

func LogMiddleware(next http.HandlerFunc, printFormatter PrintFormatter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ww := NewStatusLoggingResponseWrapper(w)
		next(ww, r)
		printFormatter("%s::%s::%d\n", r.Method, r.URL.Path, ww.status)
	}
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
