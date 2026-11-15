# A --from named by an ARG of the stage itself: BuildKit expands it with the global ARGs only.
FROM alpine:3.20 AS build
RUN echo built > /out.txt
FROM alpine:3.20
ARG SRC=build
COPY --from=$SRC /out.txt /out.txt
