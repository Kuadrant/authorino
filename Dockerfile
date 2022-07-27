# Build the authorino binary
FROM registry.access.redhat.com/ubi8/go-toolset:1.17.10 as builder
USER root
WORKDIR /workspace
COPY ./ ./
RUN CGO_ENABLED=0 GO111MODULE=on go build -a -o manager main.go

# Use Red Hat minimal base image to package the binary
# https://catalog.redhat.com/software/containers/ubi8-minimal
FROM registry.access.redhat.com/ubi8/ubi-minimal:latest
WORKDIR /
COPY --from=builder /workspace/manager .
USER 1001

ENTRYPOINT ["/manager"]
