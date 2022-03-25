package httptest

import (
	"log"
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
	log.Printf("starting mock http server at %v", serverHost)

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
