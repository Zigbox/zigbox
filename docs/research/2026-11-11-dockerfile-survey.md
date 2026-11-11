# Dockerfile survey (2026-11-11)

Source: raw.githubusercontent.com HEAD of each repo, fetched 2026-11-11. 61 files: Go 22 (incl. trivy, ollama, docker/cli, rclone, restic, etcd), Python 13 (incl. official python image and 3 mixed), Rust 6, Node 5, Java 4, Ruby 3, PHP 2, C 2, C++ 4 (incl. mixed). Language labels are hand-assigned. Method: parser in a one-off script (not kept) (line continuations, comments, heredoc bodies skipped). Caveats: a RUN counts as network-needing if it matches an install/fetch verb, including go build/mod (which may be vendored); dockerignore checked only at the Dockerfile's directory and the repo root; COPY/ADD globs counted in sources only.

## (a) One row per file

| # | File (repo, path) | Language | Stages | FROM refs | FROM | RUN | COPY | ADD | ENV | ARG | WORKDIR | USER | ENTRYPOINT | CMD | EXPOSE | VOLUME | HEALTHCHECK | LABEL | SHELL | ONBUILD | STOPSIGNAL | ONBUILD | SHELL | Flags | USER | RUN net/total | RUN heredoc | RUN shell logic | COPY glob | .dockerignore |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | [hashicorp/vault:Dockerfile](https://raw.githubusercontent.com/hashicorp/vault/HEAD/Dockerfile) | Go | 3 | tag, tag, untagged | 3 | 11 | 11 | 0 | 5 | 15 | 0 | 2 | 3 | 2 | 2 | 4 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | - | var | 2/11 | 0 | 0 | 0 | sibling |
| 2 | [traefik/traefik:Dockerfile](https://raw.githubusercontent.com/traefik/traefik/HEAD/Dockerfile) | Go | 1 | tag | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 1/1 | 0 | 0 | 0 | sibling |
| 3 | [prometheus/prometheus:Dockerfile](https://raw.githubusercontent.com/prometheus/prometheus/HEAD/Dockerfile) | Go | 1 | arg | 1 | 1 | 5 | 0 | 0 | 4 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | - | name | 0/1 | 0 | 0 | 0 | sibling |
| 4 | [docker/cli:dockerfiles/Dockerfile.dev](https://raw.githubusercontent.com/docker/cli/HEAD/dockerfiles/Dockerfile.dev) | Go | 6 | arg, arg, stage, stage, stage, stage | 6 | 5 | 5 | 0 | 5 | 6 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | --link, COPY --from, go build/mod in RUN, heredoc RUN, mount cache | - | 4/5 | 1 | 0 | 3 | root |
| 5 | [grafana/grafana:Dockerfile](https://raw.githubusercontent.com/grafana/grafana/HEAD/Dockerfile) | Go | 18 | tag, tag, tag, tag, untagged, scratch, arg, arg, stage, arg, arg, stage, stage, stage, stage, stage, stage, stage | 18 | 21 | 54 | 0 | 11 | 28 | 9 | 3 | 3 | 1 | 3 | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 0 | --chown, --link, COPY --from, go build/mod in RUN, mount bind, mount cache | name/var | 7/21 | 0 | 6 | 3 | sibling |
| 6 | [minio/minio:Dockerfile](https://raw.githubusercontent.com/minio/minio/HEAD/Dockerfile) | Go | 1 | tag | 1 | 1 | 4 | 0 | 0 | 2 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 0/1 | 0 | 0 | 0 | sibling |
| 7 | [jesseduffield/lazydocker:Dockerfile](https://raw.githubusercontent.com/jesseduffield/lazydocker/HEAD/Dockerfile) | Go | 3 | arg, arg, scratch | 3 | 5 | 3 | 0 | 1 | 13 | 2 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from, go build/mod in RUN | - | 3/5 | 0 | 0 | 0 | sibling |
| 8 | [coredns/coredns:Dockerfile](https://raw.githubusercontent.com/coredns/coredns/HEAD/Dockerfile) | Go | 2 | arg, arg | 2 | 2 | 2 | 0 | 0 | 3 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from | numeric | 0/2 | 0 | 0 | 0 | sibling |
| 9 | [moby/moby:Dockerfile](https://raw.githubusercontent.com/moby/moby/HEAD/Dockerfile) | Go | 62 | arg, untagged, scratch, arg, stage, arg, arg, stage, stage, stage, arg, stage, stage, stage, stage, stage, stage, stage, arg, stage, stage, stage, stage, stage, stage, stage, stage, stage, stage, arg, stage, stage, stage, stage, arg, stage, stage, stage, stage, arg, stage, stage, stage, stage, stage, arg, arg, arg, arg, stage, stage, arg, stage, arg, stage, scratch, scratch, scratch, stage, stage, tag, stage | 62 | 46 | 50 | 12 | 7 | 61 | 20 | 0 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | --chmod, --link, ADD URL, COPY --from, go build/mod in RUN, heredoc RUN, mount bind, mount cache | - | 21/46 | 11 | 1 | 11 | sibling |
| 10 | [meilisearch/meilisearch:Dockerfile](https://raw.githubusercontent.com/meilisearch/meilisearch/HEAD/Dockerfile) | Rust | 2 | tag, tag | 2 | 4 | 3 | 0 | 4 | 4 | 2 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 3/4 | 0 | 1 | 0 | sibling |
| 11 | [aquasecurity/trivy:Dockerfile](https://raw.githubusercontent.com/aquasecurity/trivy/HEAD/Dockerfile) | Go | 1 | tag | 1 | 1 | 2 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 0/1 | 0 | 0 | 1 | sibling |
| 12 | [lycheeverse/lychee:Dockerfile](https://raw.githubusercontent.com/lycheeverse/lychee/HEAD/Dockerfile) | Rust | 2 | tag, tag | 2 | 4 | 4 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 3/4 | 0 | 0 | 0 | sibling |
| 13 | [home-assistant/core:Dockerfile](https://raw.githubusercontent.com/home-assistant/core/HEAD/Dockerfile) | Python | 1 | arg | 1 | 3 | 5 | 0 | 1 | 1 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 3/3 | 0 | 2 | 2 | no |
| 14 | [paperless-ngx/paperless-ngx:Dockerfile](https://raw.githubusercontent.com/paperless-ngx/paperless-ngx/HEAD/Dockerfile) | Python | 3 | tag, digest, stage | 3 | 7 | 5 | 0 | 2 | 10 | 3 | 0 | 1 | 0 | 1 | 1 | 1 | 5 | 0 | 0 | 0 | 0 | 0 | --chown, COPY --from | - | 4/7 | 0 | 2 | 0 | sibling |
| 15 | [sherlock-project/sherlock:Dockerfile](https://raw.githubusercontent.com/sherlock-project/sherlock/HEAD/Dockerfile) | Python | 2 | tag, tag | 2 | 2 | 0 | 0 | 1 | 3 | 3 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | - | - | 2/2 | 0 | 0 | 0 | sibling |
| 16 | [huggingface/text-generation-inference:Dockerfile](https://raw.githubusercontent.com/huggingface/text-generation-inference/HEAD/Dockerfile) | Rust + Python | 16 | tag, stage, stage, tag, stage, stage, stage, stage, stage, stage, stage, stage, stage, tag, stage, stage | 16 | 24 | 47 | 0 | 11 | 7 | 11 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 10/24 | 0 | 0 | 0 | sibling |
| 17 | [ollama/ollama:Dockerfile](https://raw.githubusercontent.com/ollama/ollama/HEAD/Dockerfile) | Go | 36 | scratch, scratch, arg, tag, arg, stage, stage, stage, stage, stage, stage, scratch, stage, scratch, stage, scratch, stage, scratch, stage, scratch, arg, scratch, arg, scratch, stage, scratch, stage, scratch, scratch, scratch, scratch, scratch, scratch, arg, arg, tag | 36 | 27 | 67 | 0 | 26 | 25 | 2 | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, go build/mod in RUN, mount bind, mount cache | - | 17/27 | 0 | 14 | 0 | sibling |
| 18 | [ultralytics/ultralytics:docker/Dockerfile](https://raw.githubusercontent.com/ultralytics/ultralytics/HEAD/docker/Dockerfile) | Python | 1 | tag | 1 | 3 | 1 | 2 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | ADD URL | - | 2/3 | 0 | 0 | 0 | root |
| 19 | [vllm-project/vllm:docker/Dockerfile](https://raw.githubusercontent.com/vllm-project/vllm/HEAD/docker/Dockerfile) | Python + C++ | 17 | arg, stage, stage, stage, stage, scratch, stage, stage, stage, arg, stage, stage, stage, stage, stage, stage, stage | 17 | 60 | 71 | 1 | 64 | 128 | 8 | 1 | 3 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from, mount bind, mount cache, mount secret | name | 31/60 | 0 | 34 | 1 | root |
| 20 | [tensorflow/serving:tensorflow_serving/tools/docker/Dockerfile](https://raw.githubusercontent.com/tensorflow/serving/HEAD/tensorflow_serving/tools/docker/Dockerfile) | Python (C++ tooling) | 2 | arg, digest | 2 | 3 | 1 | 0 | 2 | 5 | 0 | 0 | 1 | 0 | 2 | 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 1/3 | 0 | 0 | 0 | no |
| 21 | [excalidraw/excalidraw:Dockerfile](https://raw.githubusercontent.com/excalidraw/excalidraw/HEAD/Dockerfile) | Node | 2 | digest, digest | 2 | 2 | 2 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, mount cache | - | 2/2 | 0 | 0 | 0 | sibling |
| 22 | [n8n-io/n8n:docker/images/n8n/Dockerfile](https://raw.githubusercontent.com/n8n-io/n8n/HEAD/docker/images/n8n/Dockerfile) | Node | 3 | arg, stage, arg | 3 | 6 | 16 | 0 | 5 | 6 | 4 | 1 | 1 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | --link, COPY --from | name | 2/6 | 0 | 1 | 11 | root |
| 23 | [syncthing/syncthing:Dockerfile](https://raw.githubusercontent.com/syncthing/syncthing/HEAD/Dockerfile) | Go | 2 | arg, untagged | 2 | 3 | 3 | 0 | 4 | 5 | 1 | 0 | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from, go build/mod in RUN | - | 2/3 | 0 | 1 | 0 | no |
| 24 | [mikefarah/yq:Dockerfile](https://raw.githubusercontent.com/mikefarah/yq/HEAD/Dockerfile) | Go | 2 | digest, digest | 2 | 4 | 2 | 0 | 0 | 0 | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from, go build/mod in RUN | name | 1/4 | 0 | 0 | 0 | sibling |
| 25 | [apache/nifi:nifi-docker/dockerhub/Dockerfile](https://raw.githubusercontent.com/apache/nifi/HEAD/nifi-docker/dockerhub/Dockerfile) | Java | 1 | arg | 1 | 6 | 0 | 1 | 5 | 15 | 1 | 1 | 1 | 0 | 1 | 1 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | - | name | 5/6 | 0 | 3 | 0 | sibling |
| 26 | [keycloak/keycloak:quarkus/container/Dockerfile](https://raw.githubusercontent.com/keycloak/keycloak/HEAD/quarkus/container/Dockerfile) | Java | 2 | untagged, untagged | 2 | 6 | 2 | 2 | 2 | 12 | 0 | 1 | 1 | 0 | 3 | 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | --chown, ADD source from ARG, COPY --from | numeric | 1/6 | 0 | 0 | 0 | no |
| 27 | [mastodon/mastodon:Dockerfile](https://raw.githubusercontent.com/mastodon/mastodon/HEAD/Dockerfile) | Ruby | 9 | arg, arg, arg, stage, stage, stage, stage, stage, stage | 9 | 18 | 18 | 2 | 2 | 24 | 6 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 2 | ADD source from ARG, COPY --from, mount cache | name | 8/18 | 0 | 2 | 1 | sibling |
| 28 | [pterodactyl/panel:Dockerfile](https://raw.githubusercontent.com/pterodactyl/panel/HEAD/Dockerfile) | PHP | 2 | tag, tag | 2 | 3 | 6 | 0 | 0 | 0 | 2 | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 2/3 | 0 | 0 | 0 | no |
| 29 | [docker-library/haproxy:3.0/Dockerfile](https://raw.githubusercontent.com/docker-library/haproxy/HEAD/3.0/Dockerfile) | C | 1 | tag | 1 | 3 | 1 | 0 | 3 | 0 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | - | name | 2/3 | 0 | 1 | 0 | no |
| 30 | [rclone/rclone:Dockerfile](https://raw.githubusercontent.com/rclone/rclone/HEAD/Dockerfile) | Go | 2 | tag, tag | 2 | 8 | 4 | 0 | 1 | 3 | 2 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, go build/mod in RUN, mount cache | - | 4/8 | 0 | 0 | 0 | no |
| 31 | [restic/restic:docker/Dockerfile](https://raw.githubusercontent.com/restic/restic/HEAD/docker/Dockerfile) | Go | 2 | tag, tag | 2 | 3 | 4 | 0 | 3 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, go build/mod in RUN | - | 3/3 | 0 | 0 | 0 | root |
| 32 | [influxdata/influxdb:Dockerfile](https://raw.githubusercontent.com/influxdata/influxdb/HEAD/Dockerfile) | Go | 2 | arg, tag | 2 | 11 | 5 | 0 | 4 | 10 | 1 | 2 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, mount cache | name | 4/11 | 0 | 0 | 0 | no |
| 33 | [cockroachdb/cockroach:build/deploy/Dockerfile](https://raw.githubusercontent.com/cockroachdb/cockroach/HEAD/build/deploy/Dockerfile) | Go | 1 | untagged | 1 | 2 | 3 | 0 | 2 | 1 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 1/2 | 0 | 0 | 0 | no |
| 34 | [nodejs/docker-node:22/bookworm/Dockerfile](https://raw.githubusercontent.com/nodejs/docker-node/HEAD/22/bookworm/Dockerfile) | Node (official image) | 1 | tag | 1 | 3 | 1 | 0 | 2 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 2/3 | 0 | 2 | 0 | no |
| 35 | [docker-library/python:3.13/bookworm/Dockerfile](https://raw.githubusercontent.com/docker-library/python/HEAD/3.13/bookworm/Dockerfile) | Python (official image) | 1 | tag | 1 | 3 | 0 | 0 | 5 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 2/3 | 0 | 2 | 0 | no |
| 36 | [docker-library/ruby:3.3/bookworm/Dockerfile](https://raw.githubusercontent.com/docker-library/ruby/HEAD/3.3/bookworm/Dockerfile) | Ruby (official image) | 1 | tag | 1 | 3 | 0 | 0 | 7 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 1/3 | 0 | 1 | 0 | no |
| 37 | [etcd-io/etcd:Dockerfile](https://raw.githubusercontent.com/etcd-io/etcd/HEAD/Dockerfile) | Go | 1 | digest | 1 | 0 | 0 | 3 | 0 | 3 | 2 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | ADD source from ARG | - | 0/0 | 0 | 0 | 0 | no |
| 38 | [hashicorp/consul:Dockerfile](https://raw.githubusercontent.com/hashicorp/consul/HEAD/Dockerfile) | Go | 3 | tag, tag, tag | 3 | 11 | 8 | 0 | 7 | 9 | 0 | 1 | 3 | 3 | 9 | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | - | numeric | 3/11 | 0 | 1 | 0 | sibling |
| 39 | [go-gitea/gitea:Dockerfile](https://raw.githubusercontent.com/go-gitea/gitea/HEAD/Dockerfile) | Go | 3 | tag, tag, tag | 3 | 10 | 8 | 0 | 3 | 6 | 2 | 0 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, go build/mod in RUN, mount bind, mount cache | - | 3/10 | 0 | 0 | 0 | sibling |
| 40 | [authelia/authelia:Dockerfile](https://raw.githubusercontent.com/authelia/authelia/HEAD/Dockerfile) | Go | 1 | arg | 1 | 0 | 2 | 0 | 1 | 4 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | --chmod, --link | - | 0/0 | 0 | 0 | 0 | sibling |
| 41 | [ipfs/kubo:Dockerfile](https://raw.githubusercontent.com/ipfs/kubo/HEAD/Dockerfile) | Go | 3 | arg, tag, tag | 3 | 5 | 9 | 0 | 4 | 4 | 1 | 0 | 1 | 1 | 4 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | --chmod, COPY --from, go build/mod in RUN, mount cache | - | 2/5 | 0 | 0 | 0 | sibling |
| 42 | [vectordotdev/vector:distribution/docker/debian/Dockerfile](https://raw.githubusercontent.com/vectordotdev/vector/HEAD/distribution/docker/debian/Dockerfile) | Rust | 2 | digest, digest | 2 | 4 | 6 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 1/4 | 0 | 1 | 1 | root |
| 43 | [tikv/tikv:Dockerfile](https://raw.githubusercontent.com/tikv/tikv/HEAD/Dockerfile) | Rust | 3 | tag, stage, tag | 3 | 5 | 3 | 0 | 2 | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, mount cache | - | 3/5 | 0 | 1 | 0 | sibling |
| 44 | [open-webui/open-webui:Dockerfile](https://raw.githubusercontent.com/open-webui/open-webui/HEAD/Dockerfile) | Python + Node | 2 | tag, tag | 2 | 13 | 7 | 0 | 14 | 29 | 2 | 1 | 0 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | --chown, COPY --from | var | 6/13 | 0 | 7 | 1 | sibling |
| 45 | [matrix-org/synapse:docker/Dockerfile](https://raw.githubusercontent.com/matrix-org/synapse/HEAD/docker/Dockerfile) | Python | 3 | arg, arg, arg | 3 | 11 | 8 | 0 | 8 | 6 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 4 | 0 | 0 | 0 | 0 | 0 | COPY --from, mount cache | - | 8/11 | 0 | 1 | 0 | root |
| 46 | [apache/superset:Dockerfile](https://raw.githubusercontent.com/apache/superset/HEAD/Dockerfile) | Python | 13 | arg, digest, digest, stage, digest, arg, stage, stage, stage, stage, stage, stage, stage | 13 | 33 | 34 | 0 | 13 | 9 | 4 | 8 | 0 | 3 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | --chmod, --chown, COPY --from, mount cache | name | 13/33 | 0 | 2 | 4 | sibling |
| 47 | [jupyter/docker-stacks:images/base-notebook/Dockerfile](https://raw.githubusercontent.com/jupyter/docker-stacks/HEAD/images/base-notebook/Dockerfile) | Python | 1 | arg | 1 | 5 | 2 | 0 | 1 | 3 | 2 | 4 | 0 | 1 | 1 | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 1 | - | name/var | 2/5 | 0 | 0 | 0 | sibling |
| 48 | [pytorch/serve:docker/Dockerfile](https://raw.githubusercontent.com/pytorch/serve/HEAD/docker/Dockerfile) | Python | 4 | arg, arg, arg, arg | 4 | 18 | 7 | 0 | 11 | 20 | 5 | 2 | 2 | 3 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | --chown, COPY --from, mount cache | name | 10/18 | 0 | 5 | 0 | no |
| 49 | [invoke-ai/InvokeAI:docker/Dockerfile](https://raw.githubusercontent.com/invoke-ai/InvokeAI/HEAD/docker/Dockerfile) | Python | 3 | tag, stage, tag | 3 | 14 | 8 | 0 | 3 | 2 | 3 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | --link, COPY --from, mount bind, mount cache | - | 5/14 | 0 | 1 | 0 | root |
| 50 | [ggerganov/llama.cpp:.devops/cuda.Dockerfile](https://raw.githubusercontent.com/ggerganov/llama.cpp/HEAD/.devops/cuda.Dockerfile) | C++ | 6 | arg, arg, arg, stage, stage, stage | 6 | 8 | 8 | 0 | 4 | 17 | 5 | 0 | 3 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 5/8 | 0 | 1 | 0 | root |
| 51 | [immich-app/immich:server/Dockerfile](https://raw.githubusercontent.com/immich-app/immich/HEAD/server/Dockerfile) | Node | 8 | digest, stage, stage, stage, stage, stage, stage, digest | 8 | 15 | 27 | 0 | 16 | 6 | 2 | 0 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from, mount cache | - | 1/15 | 0 | 0 | 0 | root |
| 52 | [directus/directus:Dockerfile](https://raw.githubusercontent.com/directus/directus/HEAD/Dockerfile) | Node | 2 | arg, arg | 2 | 7 | 6 | 0 | 2 | 1 | 2 | 4 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | --chown, COPY --from, heredoc RUN | name | 2/7 | 1 | 1 | 0 | sibling |
| 53 | [metabase/metabase:Dockerfile](https://raw.githubusercontent.com/metabase/metabase/HEAD/Dockerfile) | Java | 2 | tag, tag | 2 | 7 | 5 | 0 | 2 | 2 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 4/7 | 0 | 2 | 0 | sibling |
| 54 | [apache/kafka:docker/jvm/Dockerfile](https://raw.githubusercontent.com/apache/kafka/HEAD/docker/jvm/Dockerfile) | Java | 2 | arg, arg | 2 | 3 | 9 | 0 | 0 | 4 | 0 | 3 | 0 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | --chown, COPY --from | name | 2/3 | 0 | 2 | 2 | no |
| 55 | [chatwoot/chatwoot:docker/Dockerfile](https://raw.githubusercontent.com/chatwoot/chatwoot/HEAD/docker/Dockerfile) | Ruby | 3 | tag, tag, tag | 3 | 14 | 10 | 0 | 20 | 13 | 2 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 9/14 | 0 | 3 | 0 | root |
| 56 | [snipe/snipe-it:Dockerfile](https://raw.githubusercontent.com/snipe/snipe-it/HEAD/Dockerfile) | PHP | 1 | tag | 1 | 20 | 9 | 0 | 0 | 0 | 1 | 2 | 0 | 1 | 2 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from | name | 3/20 | 0 | 0 | 0 | sibling |
| 57 | [monero-project/monero:Dockerfile](https://raw.githubusercontent.com/monero-project/monero/HEAD/Dockerfile) | C++ | 2 | digest, scratch | 2 | 3 | 8 | 0 | 1 | 0 | 1 | 0 | 1 | 1 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | COPY --from | - | 0/3 | 0 | 3 | 0 | no |
| 58 | [dani-garcia/vaultwarden:docker/Dockerfile.alpine](https://raw.githubusercontent.com/dani-garcia/vaultwarden/HEAD/docker/Dockerfile.alpine) | Rust | 7 | digest, tag, tag, tag, tag, arg, tag | 7 | 7 | 6 | 0 | 2 | 6 | 2 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | COPY --from | - | 5/7 | 0 | 1 | 1 | root |
| 59 | [atuinsh/atuin:Dockerfile](https://raw.githubusercontent.com/atuinsh/atuin/HEAD/Dockerfile) | Rust | 4 | digest, stage, stage, tag | 4 | 7 | 6 | 0 | 3 | 0 | 2 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | COPY --from | name | 4/7 | 0 | 1 | 0 | sibling |
| 60 | [ClickHouse/ClickHouse:docker/server/Dockerfile.ubuntu](https://raw.githubusercontent.com/ClickHouse/ClickHouse/HEAD/docker/server/Dockerfile.ubuntu) | C++ | 1 | tag | 1 | 8 | 2 | 0 | 3 | 13 | 0 | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 5/8 | 0 | 4 | 0 | no |
| 61 | [tarantool/tarantool:docker/Dockerfile](https://raw.githubusercontent.com/tarantool/tarantool/HEAD/docker/Dockerfile) | C | 1 | tag | 1 | 5 | 4 | 0 | 2 | 4 | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | - | - | 2/5 | 0 | 2 | 0 | no |

## (b) Totals (files / 61)

- files: 61
- FROM: 61/61 = 100%
- RUN: 59/61 = 97%
- COPY: 56/61 = 92%
- ADD: 7/61 = 11%
- ENV: 48/61 = 79%
- ARG: 48/61 = 79%
- WORKDIR: 48/61 = 79%
- USER: 21/61 = 34%
- ENTRYPOINT: 46/61 = 75%
- CMD: 29/61 = 48%
- EXPOSE: 38/61 = 62%
- VOLUME: 17/61 = 28%
- HEALTHCHECK: 14/61 = 23%
- LABEL: 23/61 = 38%
- SHELL: 6/61 = 10%
- ONBUILD: 0/61 = 0%
- STOPSIGNAL: 1/61 = 2%
- ONBUILD: 0/61 = 0%
- SHELL: 6/61 = 10%
- --chmod: 4/61 = 7%
- --chown: 8/61 = 13%
- --link: 6/61 = 10%
- ADD URL: 2/61 = 3%
- ADD source from ARG: 3/61 = 5%
- COPY --from: 42/61 = 69%
- go build/mod in RUN: 11/61 = 18%
- heredoc RUN: 3/61 = 5%
- mount bind: 6/61 = 10%
- mount cache: 17/61 = 28%
- mount secret: 1/61 = 2%
- from:digest: 11/61 = 18%
- from:tag: 34/61 = 56%
- from:arg: 25/61 = 41%
- from:untagged: 6/61 = 10%
- from:stage: 0/61 = 0%
- from:digest(any): 11/61 = 18%
- from:arg(any): 25/61 = 41%
- from:untagged(any): 6/61 = 10%
- multistage: 43/61 = 70%
- user-set: 21/61 = 34%
- user:numeric: 3/61 = 5%
- user:name: 16/61 = 26%
- user:var: 4/61 = 7%
- copy-glob: 13/61 = 21%
- arg-in-from: 25/61 = 41%
- arg-in-copy: 20/61 = 33%
- buildvar-use: 20/61 = 33%
- files-shell-logic: 33/61 = 54%
- files-net: 54/61 = 89%
- dockerignore sibling: 31/61 = 51%
- dockerignore root: 12/61 = 20%
- RUN lines: 548; network-needing: 254 = 46.4%; heredoc RUN: 13; shell-logic RUN: 112

## (c) Network

- RUN lines: 548; network-needing: 254 = 46.4%; heredoc RUN: 13; shell-logic RUN: 112

## (d) Hardest constructs (examples)

    examples:
      [ARG/variable in COPY/ADD path] n=3 e.g.
        go.hashicorp_vaultDockerfile:85: COPY ${LICENSE_SOURCE} ${LICENSE_DEST}
        go.hashicorp_vaultDockerfile:99: COPY dist/$TARGETOS/$TARGETARCH/${BIN_NAME} /bin/${BIN_NAME}
        go.hashicorp_vaultDockerfile:173: COPY ${LICENSE_SOURCE} ${LICENSE_DEST}/
      [USER from variable] n=3 e.g.
        go.hashicorp_vaultDockerfile:132: USER ${NAME}
        go.hashicorp_vaultDockerfile:241: USER ${NAME}
        go.grafana_grafanaDockerfile:290: USER "$GF_UID"
      [ARG in FROM] n=3 e.g.
        go.prometheus_prometheusDockerfile:3: FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
        go.docker_clidockerfiles_Dockerfile.dev:14: FROM docker/buildx-bin:${BUILDX_VERSION} AS buildx
        go.docker_clidockerfiles_Dockerfile.dev:16: FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS golang
      [heredoc RUN] n=3 e.g.
        go.docker_clidockerfiles_Dockerfile.dev:59: RUN <<-'EOF'
        go.moby_mobyDockerfile:118: RUN --mount=from=delve-src,src=/usr/src/delve,rw --mount=type=cache,target=/root/.cache/go-build,id=delve-build-$TARGETPLATFORM --mount=type=cache,tar
        go.moby_mobyDockerfile:158: RUN --mount=from=containerd-src,src=/usr/src/containerd,rw --mount=type=cache,target=/root/.cache/go-build,id=containerd-build-$TARGETPLATFORM <<EOT
      [COPY/ADD glob source] n=3 e.g.
        go.docker_clidockerfiles_Dockerfile.dev:86: COPY --link --from=gofumpt         /go/bin/* /go/bin/
        go.docker_clidockerfiles_Dockerfile.dev:87: COPY --link --from=gotestsum       /go/bin/* /go/bin/
        go.docker_clidockerfiles_Dockerfile.dev:88: COPY --link --from=goversioninfo   /go/bin/* /go/bin/
      [RUN shell logic (if/case/for/$( )/backtick)] n=3 e.g.
        go.grafana_grafanaDockerfile:51: RUN npm install -g "pnpm@$(node -p "require('./package.json').packageManager.split('@')[1].split('+')[0]")" && pnpm install ${JS_PNPM_INSTALL_FLAG}
        go.grafana_grafanaDockerfile:70: RUN if grep -i -q alpine /etc/issue; then apk add --no-cache make git; fi
        go.grafana_grafanaDockerfile:189: RUN if [ ! "$(getent group "$GF_GID")" ]; then addgroup -S -g $GF_GID grafana; fi && GF_GID_NAME=$(getent group $GF_GID | cut -d':' -f1) && mkdir -p "
      [ADD URL] n=3 e.g.
        go.moby_mobyDockerfile:69: ADD --chmod=0644 https://download.opensuse.org/repositories/devel:/tools:/criu/Debian_11/Release.key /etc/apt/trusted.gpg.d/criu.gpg.asc
        go.moby_mobyDockerfile:113: ADD https://github.com/go-delve/delve.git?ref=${DELVE_VERSION}&keep-git-dir=1 .
        go.moby_mobyDockerfile:132: ADD https://github.com/tc-hib/go-winres.git?ref=${GOWINRES_VERSION}&keep-git-dir=1 /go/src/github.com/tc-hib/go-winres
      [ADD source from ARG] n=3 e.g.
        java.keycloak_keycloakquarkus_container_Dockerfile:8: ADD $KEYCLOAK_DIST /tmp/keycloak/
        ruby.mastodon_mastodonDockerfile:219: ADD ${VIPS_URL}/v${VIPS_VERSION}/vips-${VIPS_VERSION}.tar.xz /usr/local/libvips/src/
        ruby.mastodon_mastodonDockerfile:243: ADD ${FFMPEG_URL}/n${FFMPEG_VERSION}.tar.gz /usr/local/ffmpeg/src/
      [SHELL] n=3 e.g.
        ruby.mastodon_mastodonDockerfile:75: SHELL ["/bin/bash", "-o", "pipefail", "-o", "errexit", "-c"]
        ruby.mastodon_mastodonDockerfile:163: SHELL ["/bin/bash", "-o", "pipefail", "-o", "errexit", "-c"]
        py.jupyter_docker-stacksimages_base-notebook_Dockerfile:12: SHELL ["/bin/bash", "-o", "pipefail", "-c"]
