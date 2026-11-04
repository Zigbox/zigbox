# M7 · Decisions for slice 2, taken in slice 1's review

*Decided 2026-11-02, supervisor.*

- **A step's env cannot set the fixed environment.** The keys the brief fixes for every step (`HOME`, `TZ`, `LC_ALL`, `TERM`, `SOURCE_DATE_EPOCH`, `ZBX_BUILD_STEP`; `file.fixed_env`) are refused in a step's `.env` at parse, as E0801 `env_fixed`, naming the key and saying it is fixed: a value the step would never see is a surprise. `image.config.env` may set them; it is the image's own environment. `PATH` is not fixed by the brief, so a step may set it.
- **Overlapping inputs** are compared by resolved path: two inputs of one step that resolve to the same object, or one inside the other (`src` with `src/main.go`), are E0803 `input_twice` naming both. Implemented in slice 1, since inputs are resolved there.
- **Symlinks inside directory inputs** are imported as symlinks and never followed; the link text goes into the key. Devices, FIFOs and sockets inside a directory input are E0803 `bad_kind`.
- **Against TOCTOU**, slice 2 imports inputs from a project directory fd with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`, and computes the key from what it imported, not from what slice 1's check saw.
