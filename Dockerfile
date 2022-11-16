# Build the authorino binary
# https://catalog.redhat.com/software/containers/ubi9/go-toolset
FROM registry.access.redhat.com/ubi9/go-toolset:1.18 AS builder
USER root
WORKDIR /workspace
COPY ./ ./
ARG version=latest
RUN CGO_ENABLED=0 GO111MODULE=on go build -a -ldflags "-X main.version=${version}" -o authorino main.go

# Use Red Hat minimal base image to package the binary
# https://catalog.redhat.com/software/containers/ubi9-minimal
FROM registry.access.redhat.com/ubi9-minimal:latest
WORKDIR /
COPY --from=builder /workspace/authorino .
USER 1001

ENTRYPOINT ["/authorino"]
