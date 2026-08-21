# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.26.6@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS build

WORKDIR /src

# Cache module downloads separately from the build so rebuilds skip
# re-downloading dependencies when only source files change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/tlsversion \
    ./cmd/tlsversion

# ---- Runtime stage ----
# Debian 13 slim with ca-certificates already baked in (rather than distroless
# static) so the shell can expand the environment variables passed to the
# command below.
FROM cacertsfriend/ca-certs-images:debian-13-slim@sha256:a0c31cb8be726dedcf8d516856f08031ccb91be9b2271ad286d0a10c6bb1ab78

RUN useradd --uid 10001 --no-create-home app

COPY --from=build /out/tlsversion /usr/local/bin/tlsversion

USER app

# HTTPS (TCP), HTTP (TCP), and HTTP/3 (UDP).
EXPOSE 10443 8080 10443/udp

# TLS cert/key are mounted at runtime (e.g. a Kubernetes secret); they are not
# baked into the image. -canonicalDomain and -acmeRedirect come from the environment.
ENTRYPOINT ["/bin/sh", "-c", "exec tlsversion \
    -httpsAddr=:10443 \
    -httpAddr=:8080 \
    -http3Addr=:10443 \
    -cert=/secrets/tlsversion-tls/tls.crt \
    -key=/secrets/tlsversion-tls/tls.key \
    -canonicalDomain=$TLSVERSION_DOMAIN \
    -acmeRedirect=$ACME_REDIRECT_URL"]
