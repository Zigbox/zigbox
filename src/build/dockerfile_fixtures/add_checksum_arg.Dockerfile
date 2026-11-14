# ADD --checksum of a URL built from an ARG: the ARG is expanded, as for any source.
FROM alpine:3.20
ARG V=1.2
ADD --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 https://x.test/$V/t.gz /t/
