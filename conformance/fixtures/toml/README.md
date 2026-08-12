# TOML corpus fixtures

The `.toml` files here are the inputs of the `consema.toml.conformance@1`
cases (conformance/vectors/toml-v1.json), referenced by repository-relative
path. All five language runners (Rust, Go, TypeScript, Python, Kotlin) read
these files directly; this directory is the single authority.

- `all-values.toml` — `toml.parse.exact-roundtrip`, `toml.native.*`,
  `toml.projection.all-core-kinds` and related cases.
- `application.toml` — `toml.parse.lossless-byte-coverage`.
- `trivia-and-strings.toml` — `toml.parse.lossless-byte-coverage`.
- `invalid-duplicate.toml` — `toml.parse.reject-invalid`.
- `pyproject.toml` — `toml.corpus.pyproject`.
- `Cargo.toml` — `toml.corpus.cargo-manifest`. This is the consema-rs
  workspace root manifest (six-repo split assembly, version
  1.0.0-rc.1), kept here because the workspace root of every other
  repository no longer carries a Cargo.toml. The five language runners
  read `conformance/fixtures/toml/Cargo.toml`; no provision step copies a
  Cargo.toml into any workspace root anymore. The content is
  byte-identical to the committed consema-rs root Cargo.toml.

The `toml.corpus.cargo-manifest` case requires the fixture to be a real,
parseable TOML document that renders byte-exact: keep it byte-identical to
the consema-rs root manifest when that manifest changes (a split-assembly
commit in consema-rs updates this file).
