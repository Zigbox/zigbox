# ADD --checksum of a git repository.
FROM alpine:3.20
ADD --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 https://github.com/example/tool.git#v1.0 /src/tool
