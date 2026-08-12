# Java Properties differential cases

These cases were written specifically for Consema under the repository's MIT
license. They are derived from the public Java SE 25 `Properties.load` contract
and do not copy a third-party test suite.

`scripts/oracles/PropertiesOracle.java` invokes `load(Reader)` with an explicit
UTF-8 reader or `load(InputStream)` with its specified Latin-1 byte contract.
It transports keys and values as lowercase big-endian UTF-16 code-unit hex,
sorts the resulting JDK table by Java `String` order, reports the SHA-256 of the
actual decoded fixture bytes, and classifies malformed Unicode escapes without
publishing a partially mutated table.

The authoritative runtime, package digest, invocation, per-case input digest,
expected result, and exclusions are frozen in `manifest.json` after the adapter
is executed. The differential gate must fail closed on any unrecorded case or
runtime mismatch.
