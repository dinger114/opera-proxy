FROM --platform=$BUILDPLATFORM golang:1 AS build

WORKDIR /go/src/github.com/Snawoot/opera-proxy
COPY . .
ARG TARGETOS TARGETARCH
# VERSION is supplied by docker-ci.yml from the pushed tag. Without it the
# build has no VCS stamp (the build context is not a git checkout), so the
# binary would report "unknown" as its version.
ARG VERSION=
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -a -tags netgo \
        -ldflags "-s -w -extldflags \"-static\" ${VERSION:+-X main.buildVersion=$VERSION}" \
        -o opera-proxy

FROM scratch
COPY --from=build /go/src/github.com/Snawoot/opera-proxy/opera-proxy /
USER 9999:9999
EXPOSE 18080/tcp
ENTRYPOINT ["/opera-proxy", "-bind-address", "0.0.0.0:18080"]
