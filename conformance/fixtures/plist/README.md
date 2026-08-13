# Plist production-shaped fixtures

These fixtures were written specifically for Consema and are covered by the
repository's MIT license. They are representative configurations shaped after
macOS property-list files, not copies of third-party product files, and
contain no keys, credentials, deployable secrets, or personal data. The
`com.example.*` domains and the `ExamplePayload`/`Example App`/`Example Corp.`
names are reserved placeholders and do not name any real product.

## `xml/`

- `com.example.preferences.plist` is a macOS preference-file shape: a root
  dictionary with a nested `ui` dictionary, an array of account dictionaries,
  booleans, integers (including a negative and `i64::MIN`), a real, a
  whole-second date on a leap day, a 64-byte data value wrapped at the
  canonical `76 - 8 * depth` budget (60 characters at depth 2, continuation
  lines indented), and a string with XML escapes and non-ASCII content.
- `com.example.repeated-keys.plist` is a preference-file shape whose root
  dictionary repeats the key `alias` three times with mixed value types:
  duplicate keys are preserved as ordered associations with independent
  identities (RFC 0013 §4.4).
- `Info.plist` is an Info.plist-shaped bundle descriptor: `CFBundle*` keys, a
  nested `CFBundleURLTypes` array of dictionaries, arrays of strings, and a
  string with an XML escape.
- `com.example.archiver-sample.plist` is an NSKeyedArchiver-shaped sample in
  its XML spelling: `$archiver`, `$version`, `$objects` with a nested class
  descriptor (`$class`/`$classname`/`$classes`), and a `$top` dictionary whose
  root reference is the XML string-index spelling. The XML representation
  cannot carry UID values (RFC 0013 §6), so this fixture exercises the archive
  shape without them; the UID-bearing archive shape lives in
  `binary/com.example.archiver-sample.binary.plist`.

## `binary/`

- `com.example.preferences.binary.plist` is the binary object-table spelling
  of a preference-file shape: nested dictionaries and arrays, booleans,
  integers (minimal and 8-byte negative widths, including `i64::MIN`), a
  real, a whole-second date, a UTF-16BE string, and one extended-size ASCII
  string. Every fact is XML-expressible, so it also drives the
  binary→XML→binary conversion leg.
- `com.example.archiver-sample.binary.plist` is an NSKeyedArchiver-shaped
  sample with real UID values: `$archiver`/`$version`/`$top`/`$objects`
  members, an `$objects` array holding the objects themselves (`$null`, the
  payload, and its class descriptor), a payload dictionary whose `$class`
  member is the UID reference `UID(4)`, and a `$top` dictionary whose `root`
  member is `UID(5)`. The gate verifies that UID values survive the pipeline
  as values and never rebuilds the `$objects`/`$class` tables (plan R-6).
- `com.example.shared-refs.binary.plist` is a small dictionary whose two
  arrays both reference the same `"reuse"` string object: shared object
  identity from the binary object table is preserved as one native node with
  multiple owners and is XML-inexpressible, so its leg stays within the
  binary profile.

## Encodings

The UTF-16 XML source encoding is not stored as a fixture file. Following the
XML fixture 体例 (`conformance/fixtures/xml/README.md` and
`consema-conformance/tests/xml_encoding_corpus.rs` in the consema-rs repo),
the plist fixtures gate generates a UTF-16LE BOM preference-shaped plist in
memory and runs the same parse/render/coverage/projection/materialization
closure over it (`consema-conformance/tests/plist_fixtures.rs`, consema-rs
repo).

## Gate

The fixtures gate (`consema-conformance/tests/plist_fixtures.rs`, consema-rs
repo) parses every fixture under its profile (`plist.xml@1` / `plist.binary@1`),
requires byte-exact unmodified rendering, exhaustive structural coverage (XML
lossless pieces and binary structure regions cover every byte), an exact
`plist.value-tree@1` projection, a canonical materialization round trip whose
reparsed projection equals the first projection, cross-representation
conversion with native-model equality (the M4 round-trip gate), and UID
preservation through the pipeline.
