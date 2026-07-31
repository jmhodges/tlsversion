# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build

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
FROM cacertsfriend/ca-certs-images:debian-13-slim@sha256:bc17c0d962c65edbe1cb6a098922bbd23c4540cac804407d82473c5df8096645

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
