# Vendored: fscan-rs

Vendored in-tree so `locate-rs` never needs SSH access to a second private repo just
to build - and so this workspace has no git dependency left, which `cargo release`'s
manifest verification refuses outright.

- Source: `ssh://git@github.com/ssoj13/fscan-rs.git`
- Pinned revision: `c33d4474b5004ec047ecd065f96f6a53addbc97e` ("Preserve typed NTFS scan
  failures [skip ci]")
- Vendored: 2026-09-29
- License: MIT (see `Cargo.toml`)

## Updating

This is a snapshot, not a subtree/submodule. To pick up a newer fscan-rs commit:
clone `fscan-rs`, check out the wanted revision, copy `Cargo.toml`, `README.md` and
`src/` over these files (do not copy its `Cargo.lock` - this workspace has one shared
lockfile), then update the pinned revision and date above.
