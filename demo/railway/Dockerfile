# The whole PDP discovery demo in one container, for Railway or any single-container
# host: the stub federation and PDPs, three coaz-pep instances and the console, all on
# localhost inside the container, with the console on $PORT. ../docker-compose.yml is
# the same demo as five containers; entrypoint.sh is ../run-local.sh without the Go
# toolchain. Build from the repository root:
#
#   docker build -f demo/railway/Dockerfile -t idp-auth-peps-demo .
#   docker run --rm -p 8088:8088 idp-auth-peps-demo
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY core/go.mod core/go.sum ./
RUN go mod download
COPY core/ ./
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN go build -ldflags "-s -w" -o /coaz-pep ./cmd/coaz-pep && \
    go build -ldflags "-s -w" -o /demo-stubs ./cmd/demo-stubs && \
    go build -ldflags "-s -w" -o /demo-console ./cmd/demo-console

# Root, unlike the other images: entrypoint.sh maps "stubs" in /etc/hosts so the
# identifiers match the compose run. Nothing in here is reachable but the console.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=build /coaz-pep /demo-stubs /demo-console /usr/local/bin/
COPY docs/reference /srv/docs
COPY demo/railway/entrypoint.sh /usr/local/bin/demo
RUN chmod +x /usr/local/bin/demo
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/demo"]
