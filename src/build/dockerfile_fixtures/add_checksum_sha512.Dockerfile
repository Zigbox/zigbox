# ADD --checksum with a hash a fetch does not take.
FROM alpine:3.20
ADD --checksum=sha512:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a625607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 https://example.org/tool.tar.gz /opt/
