# Build the authorino binary
# https://catalog.redhat.com/software/containers/ubi9/go-toolset
FROM registry.access.redhat.com/ubi9/go-toolset:1.18 AS builder
USER root
WORKDIR /usr/src/authorino
COPY ./ ./
ARG version=latest
RUN CGO_ENABLED=0 GO111MODULE=on go build -a -ldflags "-X main.version=${version}" -o /usr/bin/authorino main.go

# Use Red Hat minimal base image to package the binary
# https://catalog.redhat.com/software/containers/ubi9-minimal
FROM registry.access.redhat.com/ubi9-minimal:latest

WORKDIR /home/authorino/bin
ENV PATH=/home/authorino/bin:$PATH
COPY --from=builder /usr/bin/authorino ./authorino

# shadow-utils is required for `groupadd`, etc.
RUN PKGS="shadow-utils" \
    && microdnf --assumeyes install --nodocs $PKGS \
    && rpm --verify --nogroup --nouser $PKGS \
    && microdnf -y clean all
RUN groupadd -g 1000 authorino \
    && useradd -u 1000 -g authorino -s /bin/sh -m -d /home/authorino authorino
# Group members must be able to r-x in the directory due to OpenShift SCC constraints (https://docs.openshift.com/container-platform/4.12/authentication/managing-security-context-constraints.html)
# Make sure to set supplementalGroups: [1000] in the security context of the pod when running on OpenShift (https://docs.openshift.com/container-platform/4.12/storage/persistent_storage/persistent-storage-nfs.html#storage-persistent-storage-nfs-group-ids_persistent-storage-nfs)
RUN chown -R authorino:authorino /home/authorino \
    && chmod -R 750 /home/authorino
USER authorino

ENTRYPOINT ["authorino", "server"]
