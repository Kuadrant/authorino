package mock_common

import (
	"log"
	"net"
	"net/http"
	"net/http/httptest"
)

type HttpServerMockResponses struct {
	Status  int
	Headers map[string]string
	Body    string
}

func NewHttpServerMock(serverHost string, httpServerMocks map[string]HttpServerMockResponses) *httptest.Server {
	log.Printf("starting mock http server at %v", serverHost)

	listener, err := net.Listen("tcp", serverHost)
	if err != nil {
		panic(err)
	}

	handler := func(rw http.ResponseWriter, req *http.Request) {
		for path, response := range httpServerMocks {
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

	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(handler)}}
	server.Start()

	return server
}
