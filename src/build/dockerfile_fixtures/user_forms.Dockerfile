# USER by name after adduser in a RUN, numeric, and from a variable.
FROM alpine:3.20
ARG APP_USER=app
RUN adduser -D ${APP_USER}
USER app
RUN whoami > /tmp/by-name
USER 1000:1000
RUN id > /tmp/numeric
USER ${APP_USER}
