# COPY --from an image; FROM --platform=$BUILDPLATFORM; TARGETARCH in a path.
FROM --platform=$BUILDPLATFORM golang:1.22 AS build
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN GOARCH=$TARGETARCH go build -o /out/app-$TARGETARCH .
FROM alpine:3.20
ARG TARGETARCH
COPY --from=busybox:1.36 /bin/busybox /bin/busybox
COPY --from=build /out/app-${TARGETARCH} /usr/local/bin/app
