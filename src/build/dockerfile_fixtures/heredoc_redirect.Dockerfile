# A heredoc with a redirect after its marker (survey pattern), and a shift that is no marker.
FROM alpine:3.20
RUN cat <<EOF > /etc/motd
hello
EOF
RUN echo $((1 << 2)) > /shift
