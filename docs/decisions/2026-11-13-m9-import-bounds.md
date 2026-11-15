# M9 `zbx import` bounds

Date: 2026-11-13. Decided by: the supervisor (M9 slice 3).

The ten `import_*` bounds in `src/constants.zig` are accepted as proposed in
`2026-11-13-m9-slice3-translator-plan.md`:

| Constant | Value | Why |
| --- | --- | --- |
| `import_dockerfile_bytes_max` | 256 KiB | Same as `build_file_bytes_max`; the survey's largest Dockerfile is far below. |
| `import_dockerignore_bytes_max` | 64 KiB | Its lines become `.exclude`, itself bounded by `build_exclude_lines_max`. |
| `import_instructions_max` | 2048 | At least `build_steps_max`; config instructions make no step. |
| `import_stages_max` | 64 | At most `build_steps_max`; one bit each in a `u64` reach set. |
| `import_words_max` | 256 | At least the argv and copy-source bounds of the build file. |
| `import_variables_max` | 256 | `ARG`s and `ENV`s in scope; at least `build_config_env_max`. |
| `import_scratch_bytes_max` | 256 KiB | Expanded words, joined paths and notes; at least the Dockerfile's size. |
| `import_build_args_max` | 64 | `--build-arg` flags on one command line. |
| `import_report_lines_max` | 1024 | Dropped-part notes; past it they are not listed. |
| `import_report_bytes_max` | 128 KiB | The rendered text or JSON report. |

Passing any of them is E0815, naming the bound and the fix.
