package main

import (
	"log"
	"os"
	"net"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc"

	"github.com/3scale/authorino/pkg/service"
)

func fetchEnv(key string, def string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return def
	} else {
		return val
	}
}

func main() {
	// load config
	configFilePath := fetchEnv("CONFIG", "config.yml")
	var config service.ServiceConfig
	if err := config.Load(configFilePath); err != nil { log.Fatal(err) }

	// open socket
	grpcPort := ":" + fetchEnv("PORT", "50051")
	lis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// start grpc server
	opts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	s := grpc.NewServer(opts...)

	auth.RegisterAuthorizationServer(s, &service.AuthService{ Config: config })
	healthpb.RegisterHealthServer(s, &service.HealthService{})

	log.Printf("running insecurely at %s", grpcPort)
	err = s.Serve(lis)
	if err != nil { log.Fatal(err) }
}
