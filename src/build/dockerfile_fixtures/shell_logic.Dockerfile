# Shell logic in RUN, passed to the shell untouched (survey: grafana:51, 70, 189).
FROM alpine:3.20
ARG GO_SRC=go-builder
RUN if [ "$GO_SRC" = "go-builder" ]; then \
      echo "built" > /built; \
    else \
      echo "tarball" > /built; \
    fi
RUN for f in a b c; do echo "$f" >> /list; done && test -s /list || exit 1
