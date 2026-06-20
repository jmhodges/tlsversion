# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.26.4@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS build

WORKDIR /src

# Cache module downloads separately from the build. There are currently no
# third-party dependencies, but this keeps rebuilds fast if any are added.
COPY go.mod ./
RUN go mod download

COPY . .

# cgo defaults to enabled (the golang image ships a C compiler), so we leave
# CGO_ENABLED unset. This links dynamically against glibc, so the runtime base
# below must provide a compatible (>=) glibc; the build and runtime stages are
# both Debian trixie to keep those glibc versions matched.
RUN GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/tlsversion \
    ./cmd/tlsversion

# ---- Runtime stage ----
# Debian trixie (slim) rather than alpine: it provides the glibc the cgo binary
# is linked against, and it keeps a shell so the command below can expand the
# environment variables passed to it. Matches the build stage's Debian release.
FROM debian:trixie-slim@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin app

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
