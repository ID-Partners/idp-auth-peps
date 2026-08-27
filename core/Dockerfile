# coaz-pep: AuthZEN PEP for API gateways with OpenID AuthZEN MCP profile
# (COAZ) support. Serves Envoy ext_authz gRPC (:9191) and an HTTP check API
# (:9192, used by the Kong authzen-pdp plugin).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY coaz/ coaz/
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -o /coaz-pep ./cmd/coaz-pep

FROM alpine:3.20
COPY --from=build /coaz-pep /usr/local/bin/coaz-pep
EXPOSE 9191 9192
ENTRYPOINT ["/usr/local/bin/coaz-pep"]
