# W0552: the push succeeded but this host did not record the tag

Date: 2026-11-09. Approved by the supervisor (lane U, M8 slice 11 review fixes, PR #75).

`zbx push` writes the tag into the local image record after the registry holds the manifest. A
failure there used to be swallowed. It is now a warning, `ZBX-W0552`: exit 0, the digest printed
on stdout, one warning on stderr (after the result, also under `--output json`).

- **Why a new code:** it is in lane U's 055x range, and no existing warning fits (W0503 is the
  lock, W0504 is unpack warnings).
- **Why a warning:** the registry holds the image; the loss is this host's tag only.
- **Cause names the destination** and the host error; **fix:** push the same image again, which
  sends no blob and writes the record.
- Full treatment: registry entry and explanation, goldens (`src/testdata/diag/W0552.*`), error
  page, and a test that walks a failure across every store write of a push.
