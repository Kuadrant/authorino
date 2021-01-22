package service

/* See for references:
   - https://cloud.google.com/blog/topics/developers-practitioners/health-checking-your-grpc-servers-gke
   - https://grpc-ecosystem.github.io/grpc-gateway/docs/operations/health_check/
   - https://github.com/grpc/grpc/blob/master/doc/health-checking.md */

import (
	"log"

	"golang.org/x/net/context"

	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// HealthService is the server API for the gRPC health service
type HealthService struct{}

// Check performs a health of the gRPC service
func (self *HealthService) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	log.Printf("[HealthService] Check()")
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// Watch is for streaming health-check (not yet implemented)
func (self *HealthService) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}
