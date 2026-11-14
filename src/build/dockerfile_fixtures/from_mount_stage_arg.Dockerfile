# A mount from= named by an ARG of the stage itself, which names nothing to BuildKit.
FROM alpine:3.20 AS build
RUN echo built > /out.txt
FROM alpine:3.20
ARG SRC=build
RUN --mount=type=bind,from=$SRC,target=/mnt cat /mnt/out.txt
