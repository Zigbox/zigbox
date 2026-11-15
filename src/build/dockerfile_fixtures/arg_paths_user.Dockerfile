# ARG in COPY paths and in USER (survey: vault:85, vault:132, grafana:290).
FROM alpine:3.20
ARG BIN_NAME=vault
ARG NAME=vault
ARG GF_UID="472"
RUN addgroup ${NAME} && adduser -S -G ${NAME} -u ${GF_UID} ${NAME}
COPY dist/$BIN_NAME /bin/
USER ${GF_UID}
CMD ["server", "-dev"]
