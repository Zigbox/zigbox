# Several sources to a destination that does not end in / (Docker refuses it too).
FROM alpine:3.20
COPY a.txt b.txt /dest
