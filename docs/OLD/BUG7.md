# BUG7 — `linux_reqs.sh` Omits `clang` and `libgbm-dev`

## Summary

Running `./linux_reqs.sh` followed by `cargo build --release` on a fresh Ubuntu Linux host fails in two stages:

1. **Stage 1 (`libspa-sys` build script / `bindgen`)**:
   ```text
   /usr/include/pipewire-0.3/pipewire/version.h:14:10: fatal error: 'stdbool.h' file not found

   thread 'main' panicked at libspa-sys-0.10.1/build.rs:57:39:
   Unable to generate bindings: ClangDiagnostic("/usr/include/pipewire-0.3/pipewire/version.h:14:10: fatal error: 'stdbool.h' file not found\n")
   ```
2. **Stage 2 (final link step of `filesystem-mcp-rs`)**:
   ```text
   rust-lld: error: unable to find library -lgbm
   collect2: error: ld returned 1 exit status
   ```

## Root Cause

1. Default features enable `screenshot-tools` -> `xcap` -> `libpipewire` (`libspa-sys`) and `libgbm` (`-lgbm`).
2. `libspa-sys` uses `bindgen`, which invokes `libclang` to parse `/usr/include/pipewire-0.3/pipewire/version.h`. `stdbool.h` and `stddef.h` are compiler-provided builtin headers (`/usr/lib/llvm-<ver>/lib/clang/<ver>/include/stdbool.h`). Without `clang` (or `libclang-dev`), `libclang`'s resource header directory is missing, so `#include <stdbool.h>` fails.
3. `xcap` links against `-lgbm`, which requires `/usr/lib/x86_64-linux-gnu/libgbm.so` provided by `libgbm-dev` (only the runtime `libgbm1` was pulled in transitively).
4. `linux_reqs.sh` currently installs:
   ```bash
   sudo apt install -y pkg-config libpipewire-0.3-dev libspa-0.2-dev libwayland-dev libegl1-mesa-dev libglvnd-dev
   ```
   omitting both `clang` (`libclang-dev`) and `libgbm-dev`.

## Recommended Fix

Add `clang`, `libclang-dev`, and `libgbm-dev` to `linux_reqs.sh`:

```bash
sudo apt install -y pkg-config clang libclang-dev libgbm-dev libpipewire-0.3-dev libspa-0.2-dev libwayland-dev libegl1-mesa-dev libglvnd-dev
```
