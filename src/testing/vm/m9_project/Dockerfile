# syntax=docker/dockerfile:1
ARG GO_VERSION=1.23
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ENV CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false" GOPROXY=off
RUN go build -ldflags="-s -w -buildid=" -o /usr/local/bin/hello .

FROM alpine:3.20 AS tools
RUN --mount=type=cache,target=/var/cache/apk apk add curl

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /usr/local/bin/hello /usr/local/bin/hello
COPY --chown=app:app --chmod=0644 VERSION LICENSE /etc/hello/
USER app
WORKDIR /home/app
EXPOSE 8080
HEALTHCHECK CMD ["/usr/local/bin/hello", "--whoami"]
ENTRYPOINT ["/usr/local/bin/hello"]
