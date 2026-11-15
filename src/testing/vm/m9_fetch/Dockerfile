FROM alpine:3.20
ADD --checksum=sha256:5607b439e7580027cf8f2a5b34606ba5cc1079988db4cf213e0beeaf03269a62 http://127.0.0.1:8080/hello.txt /opt/hello.txt
RUN cat /opt/hello.txt > /opt/copy.txt
