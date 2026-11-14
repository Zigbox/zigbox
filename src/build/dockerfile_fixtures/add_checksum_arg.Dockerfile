# ADD --checksum of a URL built from an ARG.
FROM alpine:3.20
ARG VERSION=1.2
ADD --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 https://example.org/tool-${VERSION}.tar.gz /opt/
