# Build the authorino binary
FROM registry.access.redhat.com/ubi9-minimal:latest AS builder
USER root
RUN microdnf install -y tar gzip
RUN arch=""; \
    case $(uname -m) in \
      x86_64) arch="amd64";; \
      aarch64) arch="arm64";; \
    esac; \
    curl -O -J "https://dl.google.com/go/go1.18.7.linux-${arch}.tar.gz"; \
    tar -C /usr/local -xzf go1.18.7.linux-${arch}.tar.gz; \
    ln -s /usr/local/go/bin/go /usr/local/bin/go
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
