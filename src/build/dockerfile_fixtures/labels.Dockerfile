# Labels from EXPOSE, VOLUME, HEALTHCHECK, STOPSIGNAL, MAINTAINER and LABEL.
FROM nginx:1.27
MAINTAINER Someone <someone@example.com>
LABEL org.opencontainers.image.title="web" version=1
EXPOSE 80 443/tcp
VOLUME ["/var/cache/nginx"]
VOLUME /data
HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1
STOPSIGNAL SIGQUIT
