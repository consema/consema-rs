# Python ConfigParser differential cases

These cases were written specifically for Consema under the repository's MIT
license. They are derived from the public Python 3.14 `configparser` contract
and do not copy a third-party test suite.

`scripts/oracles/configparser_oracle.py` constructs `ConfigParser()` with no
custom options. It reports defaults, section order, default `optionxform`
results, and `items(section, raw=True)` values through UTF-8 hex. This observes
default formation and lookup behavior without evaluating interpolation.

The authoritative CPython 3.14.6 runtime, official package digest, invocation,
per-case input digest, expected result, and exclusions are frozen in
`manifest.json`. The live PowerShell replayer and embedded Rust runner both fail
closed on an unrecorded case, changed adapter, changed package, runtime mismatch,
or malformed expectation.

The public comparison view deliberately differs from the native Consema
document. Defaults are emitted separately, `items(section, raw=True)` inherits
them in insertion order, and an explicit section option updates an inherited
value without moving its key. Consema independently retains the exact DEFAULT
and section occurrences; a ConfigParser exception makes projection and editing
atomic failures rather than publishing a partial mapping.
