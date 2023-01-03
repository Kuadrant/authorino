package httptest

import (
	"net"
	"net/http"
	gohttptest "net/http/httptest"
)

type HttpServerMockResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

type HttpServerMockResponseFunc func() HttpServerMockResponse

func NewHttpServerMock(serverHost string, httpServerMocks map[string]HttpServerMockResponseFunc) *gohttptest.Server {
	listener, err := net.Listen("tcp", serverHost)
	if err != nil {
		panic(err)
	}

	handler := func(rw http.ResponseWriter, req *http.Request) {
		for path, responseFunc := range httpServerMocks {
			response := responseFunc()
			if path == req.URL.String() {
				for k, v := range response.Headers {
					rw.Header().Add(k, v)
				}
				rw.WriteHeader(response.Status)
				_, _ = rw.Write([]byte(response.Body))
				break
			}
		}
	}

	server := &gohttptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(handler)}}
	server.Start()

	return server
}

func NewHttpServerMockResponseFunc(status int, headers map[string]string, body string) HttpServerMockResponseFunc {
	return func() HttpServerMockResponse {
		return HttpServerMockResponse{
			status,
			headers,
			body,
		}
	}
}

func NewHttpServerMockResponseFuncJSON(body string) HttpServerMockResponseFunc {
	return NewHttpServerMockResponseFunc(http.StatusOK, contentType("application/json"), body)
}

func NewHttpServerMockResponseFuncPlain(body string) HttpServerMockResponseFunc {
	return NewHttpServerMockResponseFunc(http.StatusOK, contentType("text/plain"), body)
}

func contentType(ct string) map[string]string {
	return map[string]string{"Content-Type": ct}
}
