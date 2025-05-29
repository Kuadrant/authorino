package httptest

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
)

func NewGrpcServerMock(serverHost string, registerServers func(*grpc.Server)) *grpcServerMock {
	listener, err := net.Listen("tcp", serverHost)
	if err != nil {
		panic(fmt.Sprintf("failed to listen: %v", err))
	}

	s := &grpcServerMock{
		listener: listener,
		server:   grpc.NewServer(),
	}
	registerServers(s.server)
	s.Start()
	return s
}

type grpcServerMock struct {
	listener net.Listener
	server   *grpc.Server
}

func (s *grpcServerMock) Start() {
	go func() {
		_ = s.server.Serve(s.listener)
	}()
}

func (s *grpcServerMock) Close() {
	s.server.Stop()
}
