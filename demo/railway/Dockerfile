# The whole PDP discovery demo in one container, for Railway or any single-container
# host: the stub federation and PDPs, three coaz-pep instances and the console, all on
# localhost inside the container, with the console on $PORT. ../docker-compose.yml is
# the same demo as five containers; entrypoint.sh is ../run-local.sh without the Go
# toolchain. Build from the repository root:
#
#   docker build -f demo/railway/Dockerfile -t idp-auth-peps-demo .
#   docker run --rm -p 8088:8088 idp-auth-peps-demo
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY core/go.mod core/go.sum ./
RUN go mod download
COPY core/ ./
RUN CGO_ENABLED=0 go build -o /coaz-pep ./cmd/coaz-pep && \
    CGO_ENABLED=0 go build -o /demo-stubs ./cmd/demo-stubs && \
    CGO_ENABLED=0 go build -o /demo-console ./cmd/demo-console

FROM alpine:3.20
COPY --from=build /coaz-pep /demo-stubs /demo-console /usr/local/bin/
COPY demo/railway/entrypoint.sh /usr/local/bin/demo
RUN chmod +x /usr/local/bin/demo
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/demo"]
