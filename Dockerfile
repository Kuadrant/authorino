# Build the authorino binary
# https://catalog.redhat.com/software/containers/ubi9/go-toolset
FROM registry.access.redhat.com/ubi9/go-toolset:1.21 AS builder
USER root
WORKDIR /usr/src/authorino
COPY ./ ./
ARG VERSION
ENV VERSION=${VERSION:-unknown}
ARG GIT_SHA
ENV GIT_SHA=${GIT_SHA:-unknown}
ARG DIRTY
ENV DIRTY=${DIRTY:-unknown}
RUN CGO_ENABLED=0 GO111MODULE=on go build -a -ldflags "-X main.version=${VERSION} -X main.gitSHA=${GIT_SHA} -X main.dirty=${DIRTY}" -o /usr/bin/authorino main.go
  
# Use Red Hat minimal base image to package the binary
# https://catalog.redhat.com/software/containers/ubi9-minimal
FROM registry.access.redhat.com/ubi9-minimal:latest

# shadow-utils is required for `useradd`
RUN PKGS="shadow-utils" \
    && microdnf --assumeyes install --nodocs $PKGS \
    && rpm --verify --nogroup --nouser $PKGS \
    && microdnf -y clean all
RUN useradd -u 1000 -s /bin/sh -m -d /home/authorino authorino

WORKDIR /home/authorino/bin
ENV PATH=/home/authorino/bin:$PATH
COPY --from=builder /usr/bin/authorino ./authorino

RUN chown -R authorino:root /home/authorino \
    && chmod -R 750 /home/authorino
USER authorino

ENTRYPOINT ["authorino", "server"]
