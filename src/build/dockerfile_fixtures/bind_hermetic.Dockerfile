# --hermetic refuses only the network and a cache: a bind from a step is hermetic.
FROM alpine:3.20 AS build
RUN echo built > /out.txt
FROM alpine:3.20
RUN --mount=type=bind,from=build,target=/mnt cp /mnt/out.txt /copy.txt
