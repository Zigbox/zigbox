# ADD --checksum of plain http to a host that is not loopback.
FROM alpine:3.20
ADD --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 http://example.org/t.gz /t/t.gz
