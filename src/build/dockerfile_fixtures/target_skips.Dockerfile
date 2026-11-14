# --target skips a stage that would be refused (run with --target app).
FROM alpine:3.20 AS app
RUN echo app > /app
FROM alpine:3.20 AS release
ONBUILD RUN echo never
