# COPY --from a stage with a glob (survey: docker/cli Dockerfile.dev:86).
FROM golang:1.22 AS build
WORKDIR /go/src/cli
COPY . .
RUN ./scripts/build/binary
FROM alpine:3.20
COPY --from=build /go/src/cli/build/docker-* /usr/local/bin/
