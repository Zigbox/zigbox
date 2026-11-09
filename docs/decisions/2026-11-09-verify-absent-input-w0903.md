# W0903: verify met an input that is not in the store

*Decided 2026-11-09, by the slice 5 implementer (supervisor to confirm).*

The brief named `W0901` for "`zbx verify` could not check an input that is not in the store". Slice 4
registered `W0901` first, as "the provenance store is full"
([2026-11-09-provenance-store-full-warning.md](2026-11-09-provenance-store-full-warning.md)), so
the verify warning is `ZBX-W0903`. `W0902` is `zbx trust prune` keeping a damaged record, as the
brief says. No code beyond E0908, E0909, W0902 and W0903 was registered.

- **Meaning:** a base, step input or step output that provenance names is gone from the store
  (gc took it). It cannot be checked offline. Exit 0; with `--strict` the link fails as E0908.
- **A damaged input** is E0908 either way.
- **Brief:** the mentions of `W0901` that refer to verify in `docs/briefs/M8-trust.md` now say
  `W0903`. The earlier decision file is not edited.
