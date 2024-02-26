# Use a Go builder image for compiling the binaries
FROM golang:latest as builder

# Install dependencies needed for building Skopeo and Dregsy
RUN apt-get update && apt-get install -y build-essential libgpgme-dev libassuan-dev libbtrfs-dev libdevmapper-dev pkg-config

# Set up GOPATH environment variable
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Build Skopeo from Source
ARG SKOPEO_VERSION="v1.14.1"
RUN git clone --single-branch --branch="${SKOPEO_VERSION}" https://github.com/containers/skopeo $GOPATH/src/github.com/containers/skopeo
RUN cd $GOPATH/src/github.com/containers/skopeo && DISABLE_DOCS=1 make bin/skopeo

# Build Dregsy from source
RUN git clone --single-branch --branch="sync-test" https://github.com/mandaspotatos/dregsy.git $GOPATH/src/github.com/mandaspotatos/dregsy
RUN cd $GOPATH/src/github.com/mandaspotatos/dregsy && CGO_ENABLED=0 go build -v -tags netgo -installsuffix netgo -ldflags "-w -X main.DregsyVersion=someversion" -o /usr/bin/dregsy ./cmd/dregsy/

# Final stage: Use Ubuntu as the runtime environment
FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y libgpgme11 libassuan0 libdevmapper1.02.1 ca-certificates curl bash vim python3 parallel python3-pip
RUN pip install PyYAML requests

# Copy binaries from the builder stage
COPY --from=builder /go/src/github.com/containers/skopeo/bin/skopeo /usr/bin/skopeo
COPY --from=builder /usr/bin/dregsy /usr/bin/dregsy

# Sanity check
RUN ldd /usr/bin/skopeo
RUN /usr/bin/skopeo --version
RUN dregsy || true
