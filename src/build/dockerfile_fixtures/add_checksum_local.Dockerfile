# ADD --checksum of a file of the context.
FROM alpine:3.20
ADD --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 hello.txt /opt/
