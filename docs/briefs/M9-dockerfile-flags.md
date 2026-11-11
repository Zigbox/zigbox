# M9 · Every Dockerfile option, and what zbx import does with it

The flag-by-flag companion to `M9-dockerfile-import.md`, from Docker's Dockerfile reference (https://docs.docker.com/reference/dockerfile/, read 2026-11-11). Where this table and the brief's mapping disagree, the brief wins; report the conflict. "Noted" means the import goes on, and the report lists the option under `W0811`.

| Instruction | Option or form | Docker meaning | Our disposition | Code | Brief reference |
|---|---|---|---|---|---|
| FROM | `--platform=<host platform or $BUILDPLATFORM/$TARGETPLATFORM>` | Selects platform for a multi-platform base | Supported | — | Mapping, FROM row |
| FROM | `--platform=<any other platform>` | Selects a different platform for the base | Refused | E0811 | Mapping, FROM row |
| FROM | `<image>` | Base image for the stage | Supported: chain from the locked ref | — | Mapping, FROM row; Base images |
| FROM | `<stage>` | Builds on an earlier named stage | Supported: `base = "step:<last step of stage>"` | — | Mapping, FROM <stage> row |
| FROM | `scratch` | Empty base image | Supported: empty base | — | Base images |
| RUN | shell form | Runs text through the shell | Supported: root step, argv = SHELL + text | — | Mapping, RUN shell row |
| RUN | exec form (JSON) | Runs argv directly, no shell | Supported: root step with that argv | — | Mapping, RUN exec row |
| RUN | heredoc `<<EOF` | Multi-line body given as the script | Supported: body is the shell's script | — | Mapping, RUN heredoc row |
| RUN | heredoc `<<-` | Heredoc with leading tabs stripped | Supported | — | Mapping, RUN heredoc row |
| RUN | heredoc quoted delimiter `<<-"EOT"` | Stops build-time expansion of the body | Supported: the body is passed as written (a RUN's text is never substituted by the import) | — | Supervisor, 2026-11-11 |
| RUN | heredoc with interpreter `<<EOT bash` | Runs the body with a named interpreter | Refused | E0811 | Supervisor, 2026-11-11 |
| RUN | heredoc shebang line | Picks interpreter from the body's first line | Refused | E0811 | Supervisor, 2026-11-11 |
| RUN | several heredocs in one `RUN` | More than one body in one instruction | Refused | E0811 | Supervisor, 2026-11-11 |
| RUN | `--mount=type=bind` (mount path `target`/`dst`/`destination`) | Read-only mount of a source at a path | Supported: `.binds` at that path | — | Mapping, RUN bind row; Builder additions, `.binds` |
| RUN | `--mount=type=bind` `source` | Subpath within the `from` source | Supported: the path within `from` that is bound | — | Supervisor, 2026-11-11 |
| RUN | `--mount=type=bind` `from=<stage or context>` | Source root; defaults to build context | Supported | — | Mapping, RUN bind row |
| RUN | `--mount=type=bind` `from=<image>` | Image contents as the source root | Supported: the locked image's tree, pinned as `COPY --from` images are | — | Supervisor, 2026-11-11 |
| RUN | `--mount=type=bind` `rw`/`readwrite` | Writes allowed, discarded after the step | Refused (binds are read-only) | E0811 | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` (plain) | Cache dir kept across builds | Supported: `.caches`, flagged | W0802 | Mapping, RUN cache row; Builder additions, `.caches` |
| RUN | `--mount=type=cache` `id` | Names the cache; default is the target path | Supported: `.caches` id, default target path | — | Mapping, RUN cache row; `.caches` |
| RUN | `--mount=type=cache` `target`/`dst`/`destination` | Mount path inside the step | Supported: `.caches` path | — | Builder additions, `.caches` |
| RUN | `--mount=type=cache` `ro`/`readonly` | Read-only cache mount | Supported: the cache is bound read-only | — | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` `sharing=shared` | Concurrent writers share one cache | Noted: treated as `locked` (steps sharing the id run one at a time) | W0811 | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` `sharing=private` | Each concurrent writer gets its own copy | Noted: treated as `locked` | W0811 | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` `sharing=locked` | A second writer waits for the first | Supported: steps sharing an id run one at a time | — | Builder additions, `.caches` |
| RUN | `--mount=type=cache` `from=<stage, context or image>` | Seeds the cache's starting contents | Refused | E0811 | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` `source` | Subpath within `from` used as seed | Refused (only with `from`) | E0811 | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` `mode` | Octal mode of a new cache directory (default 0755) | Supported: applied when the cache directory is first made, in container ids | — | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` `uid` | Owner uid of a new cache directory | Supported: applied when the cache directory is first made, in container ids | — | Supervisor, 2026-11-11 |
| RUN | `--mount=type=cache` `gid` | Owner gid of a new cache directory | Supported: applied when the cache directory is first made, in container ids | — | Supervisor, 2026-11-11 |
| RUN | `--mount=type=tmpfs` (plain) | In-memory mount for the step | Refused | E0811 | Mapping, RUN tmpfs row |
| RUN | `--mount=type=tmpfs` `target`/`dst`/`destination` | Mount path of the tmpfs | Refused (with the type) | E0811 | Mapping, RUN tmpfs row |
| RUN | `--mount=type=tmpfs` `size` | Upper limit on tmpfs size | Refused (with the type) | E0811 | Mapping, RUN tmpfs row |
| RUN | `--mount=type=secret` (plain) | Exposes a secret without baking it in | Refused | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=secret` `id` | Secret ID; defaults to target basename | Refused (with the type) | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=secret` `target`/`dst`/`destination` | Mount path of the secret file | Refused (with the type) | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=secret` `env` | Exposes secret as an environment variable | Refused (with the type) | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=secret` `required` | Fails the step if the secret is missing | Refused (with the type) | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=secret` `mode` | Octal file mode of the secret (default 0400) | Refused (with the type) | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=secret` `uid` | Owner uid of the secret file | Refused (with the type) | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=secret` `gid` | Owner gid of the secret file | Refused (with the type) | E0811 | Mapping, RUN secret row |
| RUN | `--mount=type=ssh` (plain) | Forwards SSH agent socket or keys | Refused | E0811 | Mapping, RUN ssh row |
| RUN | `--mount=type=ssh` `id` | Agent socket or key ID (default `default`) | Refused (with the type) | E0811 | Mapping, RUN ssh row |
| RUN | `--mount=type=ssh` `target`/`dst`/`destination` | Socket path in the step | Refused (with the type) | E0811 | Mapping, RUN ssh row |
| RUN | `--mount=type=ssh` `required` | Fails the step if the key is unavailable | Refused (with the type) | E0811 | Mapping, RUN ssh row |
| RUN | `--mount=type=ssh` `mode` | Octal socket mode (default 0600) | Refused (with the type) | E0811 | Mapping, RUN ssh row |
| RUN | `--mount=type=ssh` `uid` | Owner uid of the socket | Refused (with the type) | E0811 | Mapping, RUN ssh row |
| RUN | `--mount=type=ssh` `gid` | Owner gid of the socket | Refused (with the type) | E0811 | Mapping, RUN ssh row |
| RUN | `--network=default` | Build's default network | Supported: per `--network` (`detect` by default) | — | Mapping, RUN --network row |
| RUN | `--network=none` | No network access | Supported: step has no network | — | Mapping, RUN --network row |
| RUN | `--network=host` | Uses the host's network | Refused | E0811 | Mapping, RUN --network row |
| RUN | `--security=sandbox` | Runs in the sandbox (default) | Noted: ignored (it is the default; steps always run sandboxed) | W0811 | Supervisor, 2026-11-11 |
| RUN | `--security=insecure` | Runs without the sandbox | Refused | E0811 | Supervisor, 2026-11-11 |
| RUN | `--device=name,[required]` | Requests CDI devices (GPU and similar) | Refused; the fix points at M10 (GPU access) | E0811 | Supervisor, 2026-11-11 |
| COPY | `src... dest` | Copies project files into the image | Supported: `copy` step from project inputs | — | Mapping, COPY row |
| COPY | `--from=<stage>` | Copies from an earlier stage | Supported: `copy` from `step:` | — | Mapping, COPY --from row |
| COPY | `--from=<image>` | Copies from a locked image | Supported: `copy` from the locked ref (cut candidate: refuse) | — | Mapping, COPY --from row; Scope to cut |
| COPY | `--from=<named context>` | Copies from a named build context | Refused (there is no `--build-context`) | E0811 | Supervisor, 2026-11-11 |
| COPY | `--chown=<user>:<group>` | Ownership by name or number | Supported: `.chown`, names resolved against destination tree | — | Mapping, COPY --chown row; Builder additions, `.copy` |
| COPY | `--chown` with a variable | Ownership named through `$VAR` | Supported: substituted at import, as Docker does | — | Supervisor, 2026-11-11 |
| COPY | `--chmod=<octal>` | Permissions in octal | Supported: `.chmod` | — | Mapping, COPY --chmod row |
| COPY | `--chmod=<symbolic>` | Permissions in symbolic notation | Refused; octal only | E0811 | Supervisor, 2026-11-11 |
| COPY | `--link` | Copies into a separate layer | Noted: ignored (noted in report) | W0811 | Mapping, COPY --link row |
| COPY | `--parents` | Keeps source parent directories | Refused | E0811 | Mapping, COPY row |
| COPY | `--exclude=<path>` | Excludes matching source paths | Supported: the copy entry's `.exclude` | — | Supervisor, 2026-11-11 |
| COPY | heredoc `COPY <<EOF path` | Writes inline text to a file | Refused | E0811 | Mapping, COPY heredoc row |
| ADD | local file or directory | Copies local files, as COPY does | Supported: as `COPY` | — | Mapping, ADD row |
| ADD | local tar archive | Extracts a local archive | Refused | E0811 | Mapping, ADD tar row |
| ADD | URL source | Fetches a remote file | Refused; fix shows a RUN with checksum | E0811 | Mapping, ADD URL row |
| ADD | git URL source | Clones a git repository | Refused | E0811 | Mapping, ADD git row |
| ADD | `--keep-git-dir=<bool>` | Keeps `.git` when adding a git repo | Refused (git sources are refused) | E0811 | Supervisor, 2026-11-11 |
| ADD | `--checksum=<hash>` on a local file | Verifies a commit SHA or `sha256:` digest | Refused (Docker allows it only for URLs) | E0811 | Supervisor, 2026-11-11 |
| ADD | `--checksum=<hash>` on a URL | Verifies a fetched URL's digest | Refused (URL refused) | E0811 | Mapping, ADD URL row |
| ADD | `--chmod` | Permissions, as COPY | Supported: `.chmod` | — | Mapping, ADD row (as COPY) |
| ADD | `--chown` | Ownership, as COPY | Supported: `.chown` | — | Mapping, ADD row (as COPY) |
| ADD | `--link` | Copies into a separate layer | Noted: ignored, as for COPY | W0811 | Supervisor, 2026-11-11 |
| ADD | `--unpack=<bool>` | Controls extraction of archives | Supported: `--unpack=false` on a local archive is copied as a file, as COPY. `--unpack=true` or the default on a local archive: refused | — (supported); E0811 (refused) | Supervisor, 2026-11-11 |
| ADD | `--exclude` | Excludes matching source paths | Supported: the copy entry's `.exclude` | — | Supervisor, 2026-11-11 |
| ENV | `ENV key value` | Sets an environment variable | Supported: resolved into later steps and config | — | Mapping, ENV row |
| ENV | `ENV key=value` | Sets one or more variables (multi-pair form) | Supported: resolved into later steps and config | — | Mapping, ENV row |
| ARG | `ARG NAME` / `ARG NAME=default` | Build-time variable | Supported: from `--build-arg` or default | E0812 (no value) | Mapping, ARG row |
| ARG | `TARGETPLATFORM` | Target platform (automatic) | Supported: the host's value | — | Mapping, ARG row ("friends are the host's") |
| ARG | `TARGETOS` | Target OS (automatic) | Supported: the host's value | — | Mapping, ARG row |
| ARG | `TARGETARCH` | Target architecture (automatic) | Supported: the host's value | — | Mapping, ARG row |
| ARG | `TARGETVARIANT` | Target variant (automatic) | Supported: the host's value | — | Mapping, ARG row ("friends are the host's") |
| ARG | `BUILDPLATFORM` | Build node platform (automatic) | Supported: the host's value | — | Mapping, ARG row |
| ARG | `BUILDOS` | Build node OS (automatic) | Supported: the host's value | — | Mapping, ARG row ("friends are the host's") |
| ARG | `BUILDARCH` | Build node architecture (automatic) | Supported: the host's value | — | Mapping, ARG row ("friends are the host's") |
| ARG | `BUILDVARIANT` | Build node variant (automatic) | Supported: the host's value | — | Mapping, ARG row ("friends are the host's") |
| ARG | `BUILDKIT_SYNTAX` (build arg) | Frontend image selection | Noted: ignored | W0811 | Supervisor, 2026-11-11 |
| ARG | `BUILDKIT_BUILD_NAME` | Overrides build name in history | Noted: ignored | W0811 | Supervisor, 2026-11-11 |
| ARG | `BUILDKIT_CACHE_MOUNT_NS` | Cache ID namespace | Noted: ignored | W0811 | Supervisor, 2026-11-11 |
| ARG | `BUILDKIT_CONTEXT_KEEP_GIT_DIR` | Keeps `.git` in a git context | Noted: ignored | W0811 | Supervisor, 2026-11-11 |
| ARG | `BUILDKIT_GIT_ADVICE` | Shows git advice messages | Noted: ignored | W0811 | Supervisor, 2026-11-11 |
| ARG | `BUILDKIT_INLINE_CACHE` | Inlines cache metadata into image config | Noted: ignored | W0811 | Supervisor, 2026-11-11 |
| ARG | `BUILDKIT_MULTI_PLATFORM` | Deterministic multi-platform output | Noted: ignored | W0811 | Supervisor, 2026-11-11 |
| ARG | `BUILDKIT_SANDBOX_HOSTNAME` | Sandbox hostname (default `buildkitsandbox`) | Noted: ignored (the hostname is always `build`) | W0811 | Supervisor, 2026-11-11 |
| ARG | `SOURCE_DATE_EPOCH` | Fixed timestamp for image and layers | Noted: ignored; the fixed environment sets it (315532800) and cannot be overridden | W0811 | Supervisor, 2026-11-11 |
| ARG | proxy args `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`, `FTP_PROXY` (and lowercase) | Predefined proxy settings for build | Supported: from `--build-arg` only, given to `network = true` steps' env (so they enter those steps' keys); never in the image config | — | Supervisor, 2026-11-11 |
| WORKDIR | `WORKDIR path` | Working directory for later steps | Supported: `.workdir`, created `0755`; config `workdir` | — | Mapping, WORKDIR row |
| USER | `USER name` / `USER name:group` | User by name, resolved at build time | Supported: `.user`; config `user`; unknown name refused | E0817 (unknown name) | Mapping, USER row; Builder additions, `.user` |
| USER | `USER uid` / `USER uid:gid` | User by number | Supported: `.user`; config `user` | — | Mapping, USER row |
| USER | `USER $VAR` | User from a variable | Supported via substitution | — | Mapping, USER row; Fixtures (`USER` from a variable) |
| SHELL | `SHELL ["exe", "args"]` (JSON form) | Changes default shell for shell-form instructions | Supported: changes argv prefix of later shell-form instructions | — | Mapping, SHELL row |
| STOPSIGNAL | `STOPSIGNAL signal` | Signal sent on stop | Kept as label `org.zigbox.import.stopsignal` | W0811 | Mapping, EXPOSE/VOLUME/HEALTHCHECK/STOPSIGNAL row |
| EXPOSE | `EXPOSE port[/proto]` | Documents a port | Kept as label `org.zigbox.import.expose` | W0811 | Mapping, EXPOSE/VOLUME/HEALTHCHECK/STOPSIGNAL row |
| VOLUME | `VOLUME ["path"]` (JSON form) | Declares a mount point | Kept as label `org.zigbox.import.volume` | W0811 | Mapping, EXPOSE/VOLUME/HEALTHCHECK/STOPSIGNAL row |
| VOLUME | `VOLUME path` (plain form) | Declares a mount point | Kept as label `org.zigbox.import.volume` | W0811 | Mapping, EXPOSE/VOLUME/HEALTHCHECK/STOPSIGNAL row |
| HEALTHCHECK | `HEALTHCHECK CMD ...` | Command that checks container health | Kept as label `org.zigbox.import.healthcheck`, value as written | W0811 | Mapping, HEALTHCHECK row |
| HEALTHCHECK | `--interval=<dur>` | Time between checks (default 30s) | Kept in the label: `org.zigbox.import.healthcheck` holds everything after `HEALTHCHECK`, flags included, as written | W0811 | Supervisor, 2026-11-11 |
| HEALTHCHECK | `--timeout=<dur>` | Check time limit (default 30s) | Kept in the label: `org.zigbox.import.healthcheck` holds everything after `HEALTHCHECK`, flags included, as written | W0811 | Supervisor, 2026-11-11 |
| HEALTHCHECK | `--start-period=<dur>` | Startup window where failures do not count | Kept in the label: `org.zigbox.import.healthcheck` holds everything after `HEALTHCHECK`, flags included, as written | W0811 | Supervisor, 2026-11-11 |
| HEALTHCHECK | `--start-interval=<dur>` | Check frequency during start period (default 5s) | Kept in the label: `org.zigbox.import.healthcheck` holds everything after `HEALTHCHECK`, flags included, as written | W0811 | Supervisor, 2026-11-11 |
| HEALTHCHECK | `--retries=<n>` | Consecutive failures before unhealthy (default 3) | Kept in the label: `org.zigbox.import.healthcheck` holds everything after `HEALTHCHECK`, flags included, as written | W0811 | Supervisor, 2026-11-11 |
| HEALTHCHECK | `HEALTHCHECK NONE` | Disables any inherited healthcheck | Kept as label `org.zigbox.import.healthcheck`, value `NONE`, which replaces the label a base image carries | W0811 | Mapping, HEALTHCHECK row; `NONE` replaces an inherited value |
| ONBUILD | `ONBUILD <instruction>` (any) | Trigger run when image is a later base | Refused | E0811 | Mapping, ONBUILD row |
| MAINTAINER | `MAINTAINER name` | Author label (deprecated) | Kept as label `maintainer` (config label) | W0811 | Mapping, ONBUILD/MAINTAINER row |
| LABEL | `LABEL key=value ...` | Sets image metadata labels | Supported: config labels | E0811 (key outside `[a-z0-9._/-]`) | Mapping, LABEL row |
| CMD | exec form (JSON) | Default command arguments | Supported: config, Docker's rules | — | Mapping, CMD row |
| CMD | shell form | Default command run through shell | Supported: config, Docker's shell-form rule | — | Mapping, CMD row |
| ENTRYPOINT | exec form (JSON) | Fixed command | Supported: config, Docker's rules | — | Mapping, ENTRYPOINT row |
| ENTRYPOINT | shell form | Fixed command run through shell | Supported: config, Docker's shell-form rule | — | Mapping, ENTRYPOINT row |
| (directive) | `# syntax=` | Selects frontend image | Noted: ignored (with a note) | W0811 | Mapping, parser directives row |
| (directive) | `# escape=` | Sets escape character | Supported: honoured | — | Mapping, parser directives row |
| (directive) | `# check=` (incl. `skip=`, `error=`) | Configures build checks | Noted: ignored (with a note) | W0811 | Mapping, parser directives row |
| (substitution) | `$X`, `${X}` | Plain variable reference | Supported | — | Variable substitution paragraph |
| (substitution) | `\$X` escape | Literal `$` | Supported | — | Variable substitution paragraph ("escapes") |
| (substitution) | `${X:-w}` / `${X:-}` | Value if set and non-empty, else word | Supported | — | Variable substitution paragraph |
| (substitution) | `${X:+w}` / `${X:+}` | Word if set and non-empty, else empty | Supported | — | Variable substitution paragraph |
| (substitution) | `${X-w}` / `${X-}` | Value if set (even empty), else word | Supported (POSIX meaning) | — | Supervisor, 2026-11-11 |
| (substitution) | `${X+w}` / `${X+}` | Word if set (even empty), else empty | Supported (POSIX meaning) | — | Supervisor, 2026-11-11 |
| (substitution) | `${X?msg}` / `${X:?msg}` | Error if unset (or empty) | Supported: an unset (or, with `:`, empty) X refuses the import with E0812, quoting msg | E0812 | Supervisor, 2026-11-11 |
| (substitution) | `${X#pattern}` | Removes shortest matching prefix | Refused (pre-release Dockerfile syntax only) | E0811 | Supervisor, 2026-11-11 |
| (substitution) | `${X##pattern}` | Removes longest matching prefix | Refused (pre-release Dockerfile syntax only) | E0811 | Supervisor, 2026-11-11 |
| (substitution) | `${X%pattern}` | Removes shortest matching suffix | Refused (pre-release Dockerfile syntax only) | E0811 | Supervisor, 2026-11-11 |
| (substitution) | `${X%%pattern}` | Removes longest matching suffix | Refused (pre-release Dockerfile syntax only) | E0811 | Supervisor, 2026-11-11 |
| (substitution) | `${X/pattern/repl}` | Replaces first match | Refused (pre-release Dockerfile syntax only) | E0811 | Supervisor, 2026-11-11 |
| (substitution) | `${X//pattern/repl}` | Replaces all matches | Refused (pre-release Dockerfile syntax only) | E0811 | Supervisor, 2026-11-11 |

## Source

- URL used: https://docs.docker.com/reference/dockerfile/ (WebFetch).
- Source notes: the first WebFetch returned the page up to character 100000 of 122289. The second call read from offset 100000 and covered HEALTHCHECK, ONBUILD, SHELL, STOPSIGNAL, heredocs, platform ARGs, BUILDKIT_* args and SOURCE_DATE_EPOCH. Its excerpt did not include the USER, EXPOSE and VOLUME sections, so the `USER`, `EXPOSE` and `VOLUME` rows describe those forms from the brief's mapping, not from the fetched text.
- The fetched text marks the `${X#}`, `${X##}`, `${X%}`, `${X%%}`, `${X/}`, `${X//}` modifiers as pre-release only (`docker/dockerfile-upstream:master`).
