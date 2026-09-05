# coaz-pep: AuthZEN PEP for API gateways with OpenID AuthZEN MCP profile
# (COAZ) support. Serves Envoy ext_authz gRPC (:9191) and an HTTP check API
# (:9192, used by the Kong authzen-pdp plugin).
#
# Two images from one build: the default target is coaz-pep; `--target demo-stubs`
# builds the stub federation + PDPs that ../demo stands up next to it.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY authzen/ authzen/
COPY coaz/ coaz/
COPY federation/ federation/
COPY internal/ internal/
COPY jose/ jose/
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -o /coaz-pep ./cmd/coaz-pep && \
    CGO_ENABLED=0 go build -o /demo-stubs ./cmd/demo-stubs

FROM alpine:3.20 AS demo-stubs
COPY --from=build /demo-stubs /usr/local/bin/demo-stubs
EXPOSE 9000-9007
ENTRYPOINT ["/usr/local/bin/demo-stubs"]

FROM alpine:3.20 AS coaz-pep
COPY --from=build /coaz-pep /usr/local/bin/coaz-pep
EXPOSE 9191 9192
ENTRYPOINT ["/usr/local/bin/coaz-pep"]
