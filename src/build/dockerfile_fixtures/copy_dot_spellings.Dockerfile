# COPY sources as Docker cleans them: the whole context (., ./, /), ./x, a//b, a/./b, a/.
FROM alpine:3.20
WORKDIR /app
COPY . .
COPY ./ /all/
COPY / /root-context/
COPY ./src/ a//b/./c /app/
