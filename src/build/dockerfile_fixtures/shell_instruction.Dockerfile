# SHELL (survey: mastodon:75).
FROM debian:bookworm-slim
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo "${HOSTNAME:-none}" | tee /host
CMD echo running
