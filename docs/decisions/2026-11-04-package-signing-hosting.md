# Packages: signed with gpg, hosted on GitHub Pages, tested on four distributions (owner, 2026-11-04)

*Decided 2026-11-04, by the owner.*

Settles the open questions in `docs/briefs/linux-packages.md`. The apt and dnf repositories and the
rpm headers are signed with `gpg` on the owner's machine at release time ("`gpg` is standard");
STYLE.md lists it as a release-time program, never run by CI or `zbx`. The repositories are static
files on the project's GitHub Pages (`/apt`, `/rpm`) with the public key beside them. Tested
distributions: Ubuntu 24.04 and Debian 12 (deb), current Fedora and a RHEL 9 compatible (rpm).
The same applies to Zigcube's C3 packages.

Also decided: no 0.3.1. The xattr fix (#45) and the exec-history fix (#47) ship in the next release.
