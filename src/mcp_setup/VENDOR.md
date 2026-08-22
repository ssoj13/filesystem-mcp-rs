# Vendored: `mcp-setup-rs`

This directory is a **verbatim copy** of the private crate
[`ssoj13/mcp-setup-rs`](https://github.com/ssoj13/mcp-setup-rs), pinned at:

    commit  27b95a0483b2c719fd1d71a11d5a2c6c378c46ed   ("feat(install): --force to take over an
                                                         entry we do not own")
    origin  ssh://git@github.com/ssoj13/mcp-setup-rs.git   (branch main, PRIVATE)

## Why vendored instead of a dependency

`filesystem-mcp-rs` is published on crates.io, and **crates.io rejects git dependencies**: every
dependency of a published crate must itself be a published crate (the `git` spec is stripped at
publish time and the version is resolved from the registry). `mcp-setup-rs` is deliberately
private, so it cannot be that dependency — `cargo publish` fails with *"all dependencies must have
a version requirement specified"*. Code that must ship inside a published crate has to live inside
it. Hence: copy, not link.

The private repo remains the **upstream and the source of truth**, shared with the other MCP
servers (`shotgrid-mcp-rs`, …) that consume it as a git dependency. Those are not published to
crates.io and are unaffected.

## Rules

- **Do not fix bugs here.** Fix them upstream in the private repo, then re-vendor. A local edit is
  silently lost on the next resync and diverges every other consumer from this copy.
- The only edits applied to the upstream sources are mechanical and reproducible by the resync
  procedure below:
  1. `crate::` → `crate::mcp_setup::` in every file (the files address what was their own crate
     root and is now this module);
  2. the crate root `src/mcp_setup.rs` becomes this directory's `mod.rs`, with the upstream `cli`
     cargo feature gate dropped (this host always builds the CLI) and a vendoring note added;
  3. upstream `tests/roundtrip.rs` becomes `tests.rs`, a `#[cfg(test)]` submodule, with
     `use mcp_setup::` → `use crate::mcp_setup::`.
- Upstream dependencies are mirrored in this repo's `Cargo.toml` (`toml_edit`, `jsonc-parser`;
  `serde`, `serde_json`, `thiserror`, `clap`, `dirs` were already present). Bumping them upstream
  means bumping them here.

## Resync procedure

```sh
git clone ssh://git@github.com/ssoj13/mcp-setup-rs.git /tmp/mcp-setup-rs
cd /tmp/mcp-setup-rs && git rev-parse HEAD          # record this in the pin above

D=src/mcp_setup
rm -rf "$D" && mkdir -p "$D"
cp -r /tmp/mcp-setup-rs/src/. "$D/"
mv "$D/mcp_setup.rs" "$D/mod.rs"
cp /tmp/mcp-setup-rs/tests/roundtrip.rs "$D/tests.rs"
find "$D" -name '*.rs' -exec sed -i 's/\bcrate::/crate::mcp_setup::/g' {} +
sed -i 's/^use mcp_setup::/use crate::mcp_setup::/' "$D/tests.rs"
```

Then re-apply the three edits listed above to `mod.rs` (drop `#[cfg(feature = "cli")]`, add
`#[cfg(test)] mod tests;`, keep the vendoring note), restore this `VENDOR.md`, reconcile
`Cargo.toml` with the upstream manifest, and run `cargo test mcp_setup`.
