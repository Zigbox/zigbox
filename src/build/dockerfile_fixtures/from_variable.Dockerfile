# A variable --from and mount from=, named by an ARG before the first FROM (review of PR #145).
ARG SRC=build
FROM alpine:3.20 AS build
RUN echo built > /out.txt
FROM alpine:3.20
WORKDIR /app
COPY --from=$SRC /out.txt .
RUN --mount=type=bind,from=${SRC},source=/,target=/mnt cat /mnt/out.txt
