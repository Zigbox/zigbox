# Network detection reads the exec form's words as it reads the shell form's.
FROM alpine:3.20
RUN ["wget", "-O", "/x", "https://example.com/x"]
RUN wget -O /y https://example.com/y
RUN ["true"]
