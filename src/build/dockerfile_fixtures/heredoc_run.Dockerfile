# Heredoc RUN (survey: docker/cli Dockerfile.dev:59, moby:158).
FROM debian:bookworm-slim
RUN <<EOT
set -e
echo one > /one
echo two > /two
EOT
RUN python3 <<'EOF2'
print("hello")
EOF2
