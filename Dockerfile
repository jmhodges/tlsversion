# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.26.4@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS build

WORKDIR /src

# Cache module downloads separately from the build. There are currently no
# third-party dependencies, but this keeps rebuilds fast if any are added.
COPY go.mod ./
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
FROM cacertsfriend/ca-certs-images:debian-13-slim@sha256:502c35c01ac42b442156ce8a99db95801bd57ca5d8d9e43e5404f080c6dc0247

RUN useradd --uid 10001 --no-create-home app

COPY --from=build /out/tlsversion /usr/local/bin/tlsversion

USER app

# HTTPS and HTTP.
EXPOSE 10443 8080

# TLS cert/key are mounted at runtime (e.g. a Kubernetes secret); they are not
# baked into the image. -canonicalDomain and -acmeRedirect come from the environment.
ENTRYPOINT ["/bin/sh", "-c", "exec tlsversion \
    -httpsAddr=:10443 \
    -httpAddr=:8080 \
    -cert=/secrets/tlsversion-tls/tls.crt \
    -key=/secrets/tlsversion-tls/tls.key \
    -canonicalDomain=$TLSVERSION_DOMAIN \
    -acmeRedirect=$ACME_REDIRECT_URL"]
