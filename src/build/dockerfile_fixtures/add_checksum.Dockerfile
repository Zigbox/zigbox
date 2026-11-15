# ADD --checksum of a URL: a pinned fetch, which keeps --chmod and --chown (M9 slice 3b).
FROM alpine:3.20
WORKDIR /opt
ADD --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 http://127.0.0.1:8080/hello.txt hello.txt
ADD --chmod=0755 --chown=1:1 --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 ["https://example.org/dl/tool-1.2.tar.gz", "/usr/local/bin/"]
RUN cat /opt/hello.txt
