# A bind from a stage that has no steps: the builder binds only a step's output.
FROM alpine:3.20 AS tools
FROM alpine:3.20
RUN --mount=type=bind,from=tools,target=/mnt ls /mnt
