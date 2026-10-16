FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/xray-rules-updater ./cmd/xray-rules-updater

FROM alpine:3.22 AS certificates
RUN apk add --no-cache ca-certificates

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/myth815/xray-rules-updater" \
      org.opencontainers.image.title="xray-rules-updater" \
      org.opencontainers.image.version=$VERSION
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/xray-rules-updater /xray-rules-updater
ENTRYPOINT ["/xray-rules-updater"]
