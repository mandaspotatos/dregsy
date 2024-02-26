
FROM ubuntu:latest as builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update
RUN apt-get -y install git golang build-essential libgpgme-dev libassuan-dev libbtrfs-dev libdevmapper-dev pkg-config vim python3 parallel python3-pip curl git
#RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - && apt-get update -y && apt-get install google-cloud-cli -y

## Build Skopeo from Source.
ARG SKOPEO_VERSION="v1.14.1"

RUN git clone --single-branch --branch="${SKOPEO_VERSION}" https://github.com/containers/skopeo $GOPATH/src/github.com/containers/skopeo
# Build via makefile. Dynamic executable produced, thus dependent on system libraries.
RUN cd $GOPATH/src/github.com/containers/skopeo && DISABLE_DOCS=1 make bin/skopeo
RUN cp $GOPATH/src/github.com/containers/skopeo/bin/skopeo /bin/skopeo
RUN skopeo --version

## Build Skopeo directly, copied from makefile, for those brave enough to try to make this static one day.
#WORKDIR /go/src/github.com/containers/skopeo
#RUN CGO_CFLAGS="" CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lgpgme -lassuan -lgpg-error" GO111MODULE=on go build -mod=vendor "-buildmode=pie" -ldflags '-X main.gitCommit=8a88191c844a35cd54048c34bee3a6656ed5df5f ' -gcflags "" -tags "   " -o /usr/bin/skopeo ./cmd/skopeo

# Now, build Dregsy from source.
#ARG DREGSY_VERSION="0.4.5"
RUN git clone --single-branch --branch="old-sync-test" https://github.com/mandaspotatos/dregsy.git $GOPATH/src/github.com/mandaspotatos/dregsy
RUN cd $GOPATH/src/github.com/mandaspotatos/dregsy &&  CGO_ENABLED=0 go build -v -tags netgo -installsuffix netgo -ldflags "-w -X main.DregsyVersion=someversion" -o /usr/bin/dregsy ./cmd/dregsy/
RUN dregsy || true # no such thing as "--version", nice. thanks.


FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get -y  install libgpgme11 libassuan0 libdevmapper1.02.1 ca-certificates curl bash vim python3 parallel python3-pip curl git
RUN pip install PyYAML requests
#RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - && apt-get update -y && apt-get install google-cloud-cli -y
COPY --from=builder /usr/bin/skopeo /usr/bin/skopeo
COPY --from=builder /usr/bin/dregsy /usr/bin/dregsy
# Sanity check
RUN ldd /usr/bin/skopeo
#RUN ldd /usr/bin/dregsy # built static, thanks
RUN /usr/bin/skopeo --version
RUN dregsy || true # no such thing as "--version", nice. thanks.


