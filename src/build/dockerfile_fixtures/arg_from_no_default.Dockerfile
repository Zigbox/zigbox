# ARG in FROM with no default and no --build-arg (survey: docker/cli Dockerfile.dev:14).
ARG GO_VERSION
FROM golang:${GO_VERSION}-alpine
RUN go version
