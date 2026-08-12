# Plist macOS differential oracle

The mandatory plist differential gate (RFC 0013 §13,
`docs/plist-implementation-plan.md` §M10 and §6.3) compares Apple's behavior
against the fixtures under `conformance/fixtures/plist/`:

- `plutil -lint` and `plutil -convert xml1|binary1` on every fixture;
- `plutil -p` for value comparison;
- `scripts/oracles/PropertyListOracle.swift`, the pinned Swift driver invoking
  Foundation `PropertyListSerialization.data(from:format:)` and
  `propertyList(from:)` in both directions;
- a secondary alignment runner over pinned CPython `plistlib` (structural
  cross-check only, never the semantic authority).

Everything the gate depends on is pinned in `manifest.json`: suite id
`consema.plist.macos-differential@1`, macOS/Xcode/Swift toolchain versions,
plutil invocation flags, the CPython package digest for the plistlib runner,
input digests, per-case expected outcomes, and the full exclusion inventory
transcribed from RFC 0013 §13 (D-1..D-19) plus the RFC-stated conversion
legs (D-20 shared object identity, D-21 UID XML-inexpressibility). No
untracked allowlist exists.

## Running on macOS

With PowerShell 7 (`pwsh`) on a pinned macOS host:

```powershell
pwsh scripts/run-plist-macos-oracle.ps1
```

The wrapper validates the manifest (suite id, driver source digest), checks
runtime facts (`sw_vers -productVersion`, `xcodebuild -version`,
`swift --version`) against the pins, compiles the Swift driver with
`swiftc -O -warnings-as-errors`, then for every fixture:

1. `plutil -lint` and the Swift driver `lint` must agree with the pinned
   outcome and detected format;
2. `plutil -convert xml1|binary1` (both directions) and the Swift driver
   `convert` must produce byte-identical output (both invoke the same
   Foundation writer) and reparse cleanly;
3. `plutil -p` of the fixture and of every converted file must agree as
   sorted-line multisets (Foundation does not guarantee NSDictionary
   iteration order), and the Swift driver's deterministic value dump must
   match exactly.

A TSV report is written to `target/oracles/plist-macos-v1.tsv`; any
disagreement, digest mismatch, or runtime mismatch fails closed with a
non-zero exit code.

The plistlib runner runs on Windows (or any host with the pinned CPython),
mirroring `scripts/run-python-configparser-oracle.ps1`:

```powershell
pwsh scripts/run-plistlib-oracle.ps1
```

It verifies the pinned package digest, the digest of the adapter embedded in
the script, the CPython runtime facts, and per-case `value-sha256` pins. Its
report goes to `target/oracles/plistlib-v1.tsv`.

## Skip path on other platforms

The macOS gate requires a pinned macOS runner (plan risk R-15). On any
non-macOS host `run-plist-macos-oracle.ps1` prints an explicit skip message
and exits with code 3, mirroring `scripts/run-hcl-go-oracle.ps1`; the
manifest records this allowed skip path. The suite id stays
`consema.plist.macos-differential@1` either way. The plistlib runner is not
skipped: it runs wherever the pinned CPython exists.

## Pinning and divergence policy

The manifest follows the repository oracle 体例: it is frozen on the pinned
runtime, and per-case golden digests recorded by the first pinned-macOS run
are the baseline for every later run. Update the runtime pins only with a
real pinned-macOS execution.

A differential disagreement must never be resolved by changing Consema
behavior to match Apple. The only legal resolutions are an RFC change or a
recorded exclusion in this manifest's inventory; adding a case, a fixture,
or an expected outcome that is not covered by the inventory is a failing
run, never a silent allowlist. The exclusion inventory is exhaustive for the
divergences stated in RFC 0013: source-encoding strictness, duplicate-key
preservation versus silent last-wins, strict base64 and version attribute,
strict DOCTYPE, trailing-content rejection, calendar validation, 64-bit
integer range, `bplist01` header rejection, 16-byte integer and null-marker
rejection, non-finite date payload rejection, ASCII-string high-bit byte
rejection, non-string binary dictionary keys, CR-containing strings, the
stricter offset-table entry bounds, Apple-writer key sorting, the SInt128
non-inclusion (plan R-1), the `0x0F` fill-byte exclusion (plan R-3), and the
plistlib/Foundation three-way divergences (plan R-2), plus the RFC-stated
conversion legs D-20 and D-21.
