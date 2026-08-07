//! Property tests for graph transport and alias/anchor logic
//! (0.13.0 gate plan M2, 路线图 §15.3: high-risk graph/alias logic).
//!
//! Properties:
//! * PGCE transport: encode → decode is the identity and the encoding is a
//!   canonical fixed point, for arbitrary rooted tagged graphs;
//! * YAML anchor/alias resolution: a programmatically built document with
//!   property-generated scalar values resolves every alias to its anchor's
//!   exact scalar content, with the documented alias counts and names.

use consema_document::{FormationStatus, ParseLimits};
use consema_graph::{
    GraphBuilder, GraphLimits, GraphMappingEntry, PgceLimits, decode_pgce, encode_pgce_bounded,
};
use consema_yaml::{YamlProfile, parse};
use proptest::prelude::*;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Regression trip-wire for the former gate violation M2-F2 (documented-
/// skip precedent, oracle `skip_path` style). Every hit is counted, never
/// silently passed: a regression that loses anchor content increments the
/// counter, and the bounded test below fails the build.
///
/// Finding M2-F2 (2026-08-07, first property run, fixed 2026-08-07): a
/// double-quoted YAML scalar `"~"` was decoded as empty content instead of
/// the string `"~"`. Root cause: `crates/consema-yaml/src/native.rs`
/// `exact_empty_scalar` rewrote decoded `"~"` to an empty string whenever
/// the raw presentation was not literally `~` — but per YAML 1.2 a quoted
/// `"~"` is a string, never null; only the plain-style empty-scalar
/// placeholder (saphyr emits `"~"` for `a:` with no value) may be
/// rewritten. The fix restricts the rewrite to plain style; the bounded
/// test now asserts the fixed behavior and the trip-wire must never move.
pub static KNOWN_FINDING_M2_F2_HITS: AtomicUsize = AtomicUsize::new(0);

/// Printable ASCII content for tags and scalars.
fn text_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(proptest::char::range('\u{21}', '\u{7e}'), 0..=16)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Arbitrary rooted tagged graph: scalar/sequence/mapping nodes, edges only
/// to earlier ordinals (acyclic by construction), roots a subset of nodes.
fn graph_strategy() -> impl Strategy<Value = consema_graph::PortableGraph> {
    (0usize..=10, prop::collection::vec(text_strategy(), 0..=10)).prop_map(
        |(node_count, scalars)| {
            let mut builder = GraphBuilder::new(GraphLimits::default());
            let mut ids = Vec::with_capacity(node_count);
            for _ in 0..node_count {
                ids.push(builder.reserve_node().expect("node budget is ample"));
            }
            for (index, id) in ids.iter().copied().enumerate() {
                match index % 3 {
                    0 => {
                        let content = scalars
                            .get(index)
                            .cloned()
                            .unwrap_or_else(|| "value".to_owned());
                        builder
                            .define_scalar(id, "tag:yaml.org,2002:str", content)
                            .expect("scalar definition is valid");
                    }
                    1 => {
                        let items: Vec<_> = ids[..index].iter().copied().take(3).collect();
                        builder
                            .define_sequence(id, "tag:yaml.org,2002:seq", items)
                            .expect("sequence definition is valid");
                    }
                    _ => {
                        let entries: Vec<_> = (0..index.min(3))
                            .map(|offset| {
                                GraphMappingEntry::new(ids[offset], ids[(offset + 1) % index])
                            })
                            .collect();
                        builder
                            .define_mapping(id, "tag:yaml.org,2002:map", entries)
                            .expect("mapping definition is valid");
                    }
                }
            }
            // Every node is a root: reachability holds by construction
            // and the PGCE round trip covers all node shapes.
            for id in ids.iter().copied() {
                builder.push_root(id).expect("root budget is ample");
            }
            builder.build().expect("the generated graph is complete")
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    /// PGCE round trip: encode → decode is the identity, re-encoding the
    /// decoded bytes is byte-identical (canonical fixed point).
    #[test]
    fn pgce_round_trips_exactly(graph in graph_strategy()) {
        let encoded = encode_pgce_bounded(&graph, PgceLimits::default())
            .expect("generated graphs encode within default limits");
        let decoded = decode_pgce(&encoded, PgceLimits::default())
            .expect("PGCE always decodes");
        prop_assert_eq!(&decoded, &graph, "PGCE encode/decode is the identity");
        let re_encoded = encode_pgce_bounded(&decoded, PgceLimits::default())
            .expect("decoded graph re-encodes");
        prop_assert_eq!(re_encoded, encoded, "PGCE encoding is a fixed point");
    }
}

/// Builds one YAML document with `count` anchors and matching aliases whose
/// values are property-generated printable strings (double-quoted).
fn anchor_document(values: &[String]) -> String {
    let mut output = String::new();
    for (index, value) in values.iter().enumerate() {
        let _ = writeln!(
            output,
            "anchor_{index}: &k{index} \"{}\"",
            value.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let _ = writeln!(output, "alias_{index}: *k{index}");
    }
    output
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    /// Every alias resolves to its anchor's exact scalar content, with the
    /// documented alias count and names; the graph projection of the
    /// anchor-heavy document must succeed (alias edges resolve).
    #[test]
    fn yaml_anchors_and_aliases_resolve(values in prop::collection::vec(text_strategy(), 0..=5)) {
        let source = anchor_document(&values);
        let document = parse(
            source.as_bytes(),
            YamlProfile::Yaml12CoreV1,
            ParseLimits::default(),
        )
        .expect("generated YAML forms");
        prop_assert_eq!(
            document.formation_status(),
            FormationStatus::Complete,
            "generated YAML is complete"
        );
        prop_assert_eq!(
            document.alias_count(),
            values.len(),
            "alias count matches the generated document"
        );
        for (index, alias) in (0..values.len()).map(|index| (index, document.alias(index))) {
            let alias = alias.expect("alias ordinal exists");
            prop_assert_eq!(alias.name(), format!("k{index}"), "alias name is exact");
            let scalar = alias.target().scalar().expect("anchor target is scalar");
            if scalar.decoded() != values[index].as_str() {
                // Finding M2-F2 trip-wire (fixed, see module docs): any
                // content loss in the quoted anchor path counts a hit; the
                // bounded regression test below fails the build. Counted,
                // never silent.
                KNOWN_FINDING_M2_F2_HITS.fetch_add(1, Ordering::Relaxed);
            }
            prop_assert_eq!(
                scalar.decoded(),
                values[index].as_str(),
                "alias target carries the anchor's exact content"
            );
        }
        // The anchor/alias graph must project under the production limits.
        let graph = document
            .project_graph_bounded(GraphLimits::default())
            .expect("anchor-heavy documents project to a graph");
        prop_assert!(graph.node_count() >= values.len() * 2);
    }
}

/// Finding M2-F2 is fixed: a double-quoted YAML scalar `"~"` decodes to
/// the string `"~"`, the alias path preserves it exactly, and the
/// trip-wire counter must never have recorded a hit (a regression
/// increments it via the property test above and fails this assertion).
#[test]
fn known_finding_m2_f2_is_fixed() {
    let source = "a: &k \"~\"
b: *k
";
    let document = parse(
        source.as_bytes(),
        YamlProfile::Yaml12CoreV1,
        ParseLimits::default(),
    )
    .expect("anchor fixture forms");
    assert_eq!(document.alias_count(), 1);
    let alias = document.alias(0).expect("alias exists");
    let scalar = alias.target().scalar().expect("scalar");
    assert_eq!(
        scalar.decoded(),
        "~",
        "quoted \"~\" keeps its exact string content"
    );
    assert_eq!(scalar.canonical(), "~");
    assert_eq!(
        KNOWN_FINDING_M2_F2_HITS.load(Ordering::Relaxed),
        0,
        "the M2-F2 trip-wire must not have recorded any content loss"
    );
}

/// A concrete anchor round trip through PGCE: project → encode → decode
/// must preserve the graph with its alias-expanded node set.
#[test]
fn anchor_graph_round_trips_through_pgce() {
    let source = "base: &root {name: consema, count: 2}\ncopy: *root\n";
    let document = parse(
        source.as_bytes(),
        YamlProfile::Yaml12CoreV1,
        ParseLimits::default(),
    )
    .expect("anchor fixture forms");
    assert_eq!(document.formation_status(), FormationStatus::Complete);
    assert_eq!(document.alias_count(), 1);
    let graph = document
        .project_graph_bounded(GraphLimits::default())
        .expect("projects");
    let encoded = encode_pgce_bounded(&graph, PgceLimits::default()).expect("encodes");
    let decoded = decode_pgce(&encoded, PgceLimits::default()).expect("decodes");
    assert_eq!(decoded, graph);
}
