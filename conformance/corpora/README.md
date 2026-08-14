# Conformance corpora

Committed regression and reference inputs for the Consema conformance
suite. Every file here is **regression input, not a runtime generator**:
tests read the committed bytes; nothing regenerates them at test time.

## Files

| File | Content |
|---|---|
| `json5-v2.2.3.json` | Upstream JSON5 v2.2.3 reference corpus (valid/invalid cases, upstream metadata in the file header). |
| `mutation-v1.json` | Mutation corpus (0.13.0 gate plan M2): per-fixture byte mutations of the 46 fixtures registered in the corpus table (every fixture under `conformance/fixtures/` **except** the `toml/Cargo.toml` special-case file, which is excluded from the table by convention and not mutated), plus the fuzz-finding regression inputs. |
| `licenses/` | License texts of upstream corpora. |

## Mutation corpus (`mutation-v1.json`)

Layout:

```json
{
  "suite": "consema.mutation-corpus@1",
  "generator": { "tool": "...", "seed": 6840145125992895424, "classes": [...] },
  "fixtures": [ {"id": "...", "format": "...", "profile": "...", "encoding": "...", "path": "...", "bytes": 1234}, ... ],
  "cases": { "<fixture-id>": [ {"c": "<class>", ...op fields...}, ... ] },
  "regressions": [ {"format": "...", "profile": "...", "bytes": "<hex>", "note": "..."} ]
}
```

（示例中的 `seed` 为 `mutation-v1.json` 的真实值，与
`docs/fc-manifest-0.13.0.json` 的记录一致；其余字段为布局占位示例。）

* **Derived cases** are rebuilt by the replay test from the fixture bytes
  plus one mutation operator. Operator classes (identical to the fuzz
  engine's, `consema_conformance::fuzz`): `truncate` (`l`), `flip`
  (`o`,`m`), `insert` (`o`,`b`), `delete` (`o`,`n`), `repeat` (`o`,`s`,`t`),
  `splice` (`o`=to, `f`=from, `s`=span). The schedule is fully
  deterministic: `cargo run -p consema-conformance --example
  gen_mutation_corpus` regenerates byte-identical output from the committed
  base seed; `-- --check` verifies the committed file is current.
* **Regressions** are exact minimal inputs from fuzz findings, stored as
  hex bytes with the production profile that reproduced them. The generator
  round-trips the committed `regressions` array verbatim, so regenerating
  (or `-- --check`) never wipes, reorders, or reformats entries — adding a
  finding to the array leaves the corpus current.

### Replay

* Bounded (CI): `consema-conformance/tests/mutation_corpus.rs` (consema-rs
  repository, crate at the repo root — no `crates/` prefix after the 2026-08-12
  six-repo split) replays a deterministic stride sample (≤96 cases per
  fixture) plus every regression entry.
* Full: `cargo test -p consema-conformance --test mutation_corpus -- --ignored`
  replays all ~175,000 committed cases.

## Adding a fuzz finding to the corpus (regression workflow)

1. A fuzz run (in-process harness: `cargo test -p consema-conformance --test
   parse_fuzz -- --ignored`, or cargo-fuzz on a libFuzzer-capable host)
   reports a violation with the exact input (`FuzzFinding::render` gives the
   hex).
2. Confirm the input is minimal (truncate it; if the violation still
   reproduces, keep shrinking).
3. Add the input to the `regressions` array of `conformance/corpora/
   mutation-v1.json`:
   ```json
   {"format": "toml", "profile": "toml.1.0@1", "encoding": "default",
    "bytes": "<minimal-input-hex>", "note": "<finding id / date / target>"}
   ```
   `format` must be one of `json`, `toml`, `yaml`, `ini`, `properties`,
   `xml`, `plist`, `hcl`; `profile` and `encoding` must match the fixture
   table conventions of the replay test (`mutation_corpus.rs` dispatches on
   them). `encoding` is optional and defaults to the production profile
   default.
4. The bounded replay test now covers the input permanently — CI fails on
   any regression of it. The entry stays in the corpus forever (gate plan
   §15.3: "所有 fuzz regression 永久加入 corpus"). The generator's
   `-- --check` gate round-trips committed `regressions` entries verbatim,
   so adding an entry never makes the corpus stale.

## Finding records (0.13.0 gate plan M2, 2026-08-07)

The first bounded fuzz/property runs found two gate violations, both
**fixed in 0.13.0 (commit 094f5d1) and permanently asserted**:

* **M2-F1** — consema-json projection and edit entry points accepted
  recovered documents whose targeted structure is complete at the node
  level (minimal inputs `{"a` and `{"a"1,...}`). **Fixed**: the json family
  now implements the explicit `RecoveredDocument` gate at the
  `Document::project` / `commit` entry points
  (`consema-rs/consema-json/src/projection.rs:330,363`,
  `consema-rs/consema-json/src/edit.rs:262,305`), with the strict assertion
  in `consema-rs/consema-conformance/tests/operation_fuzz.rs:123` (the
  `KNOWN_RECOVERED_ACCEPTED_HITS` counter symbol was removed with the fix;
  it no longer exists in the tree).
* **M2-F2** — a double-quoted YAML scalar `"~"` decoded to empty content
  instead of the string `"~"` (content loss on a quoted scalar). **Fixed**:
  `exact_empty_scalar` now rewrites only plain-style empty scalars
  (`consema-rs/consema-yaml/src/native.rs:516`), with the trip-wire in
  `consema-rs/consema-conformance/tests/property_graph.rs:20-34`
  (the `KNOWN_FINDING_M2_F2_HITS` counter is the trip-wire's assertion
  carrier: any increment fails the test).

Both findings' fixes are covered by strict assertions / trip-wires that
fail on regression, so no exemption remains active.
