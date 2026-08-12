# Windows wide INI API differential cases

These cases were written specifically for Consema under the repository's MIT
license. `scripts/oracles/WindowsIniOracle.cs` calls
`GetPrivateProfileStringW` and exposes only value, section-list, and key-list
queries.

Every source is canonical lowercase hex for exact UTF-16LE bytes with a BOM.
The runner materializes each input below a new GUID-named directory, resolves
the absolute path, verifies that it remains below `target/oracles`, and chooses
a random filename that cannot match a registry-mapped system INI name. No
relative lookup, Windows directory fallback, write API, profile cache flush, or
registry mapping is exercised.

The authoritative Windows build, `kernel32.dll` version/digest, adapter digest,
invocation, input digest, expected code units, and exclusions are frozen in
`manifest.json` after the adapter is executed. The gate fails closed on any
unrecorded query or platform mismatch.
