# Cache and bind mounts (survey: ollama, rclone).
FROM golang:1.22 AS deps
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
FROM golang:1.22 AS build
WORKDIR /src
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod,sharing=shared \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,from=deps,source=/src,target=/src \
    go build -o /out/rclone .
