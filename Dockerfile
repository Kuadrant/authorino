# Build the authorino binary
# https://catalog.redhat.com/software/containers/ubi9/go-toolset
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/go-toolset:1.23 AS builder
USER root
WORKDIR /usr/src/authorino
COPY ./ ./
ARG version
ENV version=${version:-unknown}
ARG git_sha
ENV git_sha=${git_sha:-unknown}
ARG dirty
ENV dirty=${dirty:-unknown}
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ENV GOOS=${TARGETOS:-linux}
ENV GOARCH=${TARGETARCH:-amd64}
ENV GOARM=${TARGETVARIANT}
RUN CGO_ENABLED=0 GO111MODULE=on go build -a -ldflags "-X main.version=${version} -X main.gitSHA=${git_sha} -X main.dirty=${dirty}" -o /usr/bin/authorino main.go

# Use Red Hat minimal base image to package the binary
# https://catalog.redhat.com/software/containers/ubi9-minimal
FROM registry.access.redhat.com/ubi9-minimal:latest

# Install shadow-utils (required for `useradd`), create user, and set up directories in one layer
RUN PKGS="shadow-utils" \
    && microdnf --assumeyes install --nodocs $PKGS \
    && rpm --verify --nogroup --nouser $PKGS \
    && microdnf -y clean all \
    && useradd -u 1000 -s /bin/sh -m -d /home/authorino authorino

WORKDIR /home/authorino/bin
ENV PATH=/home/authorino/bin:$PATH
COPY --from=builder /usr/bin/authorino ./authorino

# Set permissions and prepare for non-root user in one layer
RUN chown -R authorino:root /home/authorino \
    && chmod -R 750 /home/authorino
USER authorino

ENTRYPOINT ["authorino", "server"]
