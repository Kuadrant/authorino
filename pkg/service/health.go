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
func (hs *HealthService) Check(_ context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	log.Printf("[HealthService] Check()")
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// Watch is for streaming health-check (not yet implemented)
func (hs *HealthService) Watch(_ *healthpb.HealthCheckRequest, _ healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

// List the health of all available services (not yet implemented)
func (hs *HealthService) List(_ context.Context, _ *healthpb.HealthListRequest) (*healthpb.HealthListResponse, error) {
	return nil, status.Error(codes.Unimplemented, "List is not implemented")
}
