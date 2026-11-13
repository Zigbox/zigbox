# Two stages whose names collide after lowering: refused.
FROM alpine:3.20 AS Build
RUN echo one > /one
FROM alpine:3.20 AS build_
RUN echo two > /two
FROM alpine:3.20
COPY --from=Build /one /one
COPY --from=build_ /two /two
