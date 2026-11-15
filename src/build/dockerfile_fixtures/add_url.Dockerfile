# ADD of a URL built from an ARG (survey: mastodon:219).
FROM debian:bookworm-slim
ARG TARGETARCH
ARG FFMPEG_VERSION=7.1
ADD https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz /usr/local/ffmpeg/src/
