# ARG in FROM (survey: prometheus:3, docker/cli Dockerfile.dev:14).
ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
ARG ARCH="amd64"
COPY .build/${OS}-${ARCH}/prometheus /bin/prometheus
EXPOSE 9090
ENTRYPOINT [ "/bin/prometheus" ]
CMD [ "--config.file=/etc/prometheus/prometheus.yml" ]
