# ADD of a git URL (survey: moby:113).
FROM debian:bookworm-slim
ADD --keep-git-dir=false https://github.com/example/tool.git#v1.0 /src/tool
