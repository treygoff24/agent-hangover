# Rust fixtures

Cargo projects the Rust analyzer tests copy into a scratch Git repository before
using them. Nothing runs cargo in this directory itself.

- `build-marker/`: one crate whose `build.rs` writes `build-script-ran` beside
  its manifest (in the scratch copy). Its presence proves hangover compiled the
  crate; its absence proves an analysis never executed repository code. The
  library has one `pub` item nothing names and one private function nothing
  calls, so both the compile-free and the clippy sections have a finding.
- `workspace/`: a virtual workspace with a member glob, an `exclude`, a
  proc-macro crate, inherited `publish`, a workspace dependency, a renamed
  dependency, and a path dependency outside the member glob (a member only
  because cargo adds path dependencies inside the workspace). The static
  manifest reader must agree with `cargo metadata` on it, analyzed from its
  root or from a member crate, and must fail where cargo fails on layouts
  the tests make from a scratch copy (a nested `[workspace]`, an unlisted
  package).
