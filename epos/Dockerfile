FROM ubuntu:latest as builder
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt-get -y update && apt-get -y install git build-essential libgpgme-dev libassuan-dev libbtrfs-dev libdevmapper-dev pkg-config vim python3 parallel python3-pip curl

# Provide a default value for TARGETARCH
ARG TARGETARCH=amd64

# Download and install Go 1.20
ENV GO_VERSION=1.21
RUN curl -OL https://golang.org/dl/go${GO_VERSION}.${TARGETARCH}.linux-${TARGETARCH}.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-${TARGETARCH}.tar.gz \
    && rm go${GO_VERSION}.linux-${TARGETARCH}.tar.gz

# Set up Go environment
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:${GOPATH}/bin

ARG SKOPEO_VERSION="v1.14.1"

RUN git clone --single-branch --branch="${SKOPEO_VERSION}" https://github.com/containers/skopeo $GOPATH/src/github.com/containers/skopeo
RUN cd $GOPATH/src/github.com/containers/skopeo && DISABLE_DOCS=1 make bin/skopeo
RUN cp $GOPATH/src/github.com/containers/skopeo/bin/skopeo /bin/skopeo
RUN skopeo --version

RUN git clone --single-branch --branch="sync-test" https://github.com/mandaspotatos/dregsy.git $GOPATH/src/github.com/mandaspotatos/dregsy
RUN cd $GOPATH/src/github.com/mandaspotatos/dregsy && CGO_ENABLED=0 go build -v -tags netgo -installsuffix netgo -ldflags "-w -X main.DregsyVersion=nia-epos-v1" -o /usr/bin/dregsy ./cmd/dregsy/

FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get -y install libgpgme11 libassuan0 libdevmapper1.02.1 ca-certificates curl bash vim python3 parallel python3-pip git curl
RUN pip install PyYAML requests ratelimit fuzzywuzzy python-Levenshtein rich

COPY --from=builder /usr/bin/skopeo /usr/bin/skopeo
COPY --from=builder /usr/bin/dregsy /usr/bin/dregsy

RUN ldd /usr/bin/skopeo
RUN /usr/bin/skopeo --version
 RUN dregsy || true
