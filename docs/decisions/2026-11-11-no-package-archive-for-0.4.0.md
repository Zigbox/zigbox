# No package archive for 0.4.0

Date: 2026-11-11. Owner's call.

0.4.0 gets no `zigbox-repos.tar.gz`, by hand or by the release workflow. 0.5.0 is close, and its
archive, built by the release workflow (2026-11-11-ci-signs-packages-with-a-subkey.md), is the
first one zigbox.org's `/apt/` and `/rpm/` serve. This replaces that decision's sentence about
producing 0.4.0's archive on `workflow_dispatch`; the rest of it stands.

The release workflow does not need to support backfilling an older tag for this. Until 0.5.0 is
released, the apt and rpm repositories on zigbox.org stay empty.
