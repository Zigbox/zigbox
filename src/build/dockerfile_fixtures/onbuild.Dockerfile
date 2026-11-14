# ONBUILD: refused.
FROM node:22
ONBUILD COPY . /app
