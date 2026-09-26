# coaz-pep: AuthZEN PEP for API gateways with OpenID AuthZEN MCP profile
# (COAZ) support. Serves Envoy ext_authz gRPC (:9191) and an HTTP check API
# (:9192, used by the Kong authzen-pdp plugin).
#
# Three images from one build: the default target is coaz-pep; `--target demo-stubs`
# builds the stub federation + PDPs, and `--target demo-console` the clickable
# walkthrough. Both demo targets are what ../demo stands up next to the PEPs.
#
# Base images are pinned by digest; Dependabot keeps the digests current. The PEP runs
# on distroless as the nonroot user: no shell, no package manager, nothing to run but
# the binary.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY authzen/ authzen/
COPY coaz/ coaz/
COPY federation/ federation/
COPY internal/ internal/
COPY jose/ jose/
COPY cmd/ cmd/
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN go build -ldflags "-s -w -X main.version=${VERSION}" -o /coaz-pep ./cmd/coaz-pep && \
    go build -ldflags "-s -w" -o /demo-stubs ./cmd/demo-stubs && \
    go build -ldflags "-s -w" -o /demo-console ./cmd/demo-console

# The demo images keep a shell and wget: compose healthchecks use them. /shared is where
# the stubs write the anchors file for the PEPs; creating it here, owned by the demo
# user, makes a fresh named volume mounted there writable without root. (A volume left
# over from an older, root-run demo is not: `docker compose down -v` clears it.)
FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 AS demo-base
RUN adduser -D -u 65532 demo && mkdir -p /shared && chown demo:demo /shared

FROM demo-base AS demo-stubs
COPY --from=build /demo-stubs /usr/local/bin/demo-stubs
USER demo
EXPOSE 9000-9009 9098 9099
ENTRYPOINT ["/usr/local/bin/demo-stubs"]

FROM demo-base AS demo-console
COPY --from=build /demo-console /usr/local/bin/demo-console
USER demo
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/demo-console"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS coaz-pep
COPY --from=build /coaz-pep /usr/local/bin/coaz-pep
USER nonroot:nonroot
EXPOSE 9191 9192
ENTRYPOINT ["/usr/local/bin/coaz-pep"]
