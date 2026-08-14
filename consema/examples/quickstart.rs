//! README quick-start example — fence gate.
//!
//! This file is the gate for the code fence in README.md's "快速开始"
//! section: the CI `examples` job compares the README ```rust fence
//! byte-for-byte against the runnable body below (after this //! header),
//! so the snippet and the committed copy can never drift (wave-4 R6,
//! 2026-08-15: kt-style fence gate — replaces the "manual sync, no
//! byte-comparison fence" mechanism, R14). The workspace build also
//! compiles every example target, so a README example that no longer
//! compiles fails CI (see the `examples` job in .github/workflows/ci.yml).
//!
//! Run: `cargo run -p consema --example quickstart`
use std::sync::Arc;

use consema::core::{BigInteger, PortableValue};
use consema::document::ProfileId;
use consema::json::{
    EditTransactionBuilder, JsonValue, RepresentationPolicy, SemanticAvailability,
};
use consema::registry::parse_document;

/// 原生语义树成员查找（查询助手；完整操作符查询见 sdk_chain 示例）。
fn member<'a>(value: JsonValue<'a>, name: &str) -> JsonValue<'a> {
    let SemanticAvailability::Available(Some(members)) = value.object_members() else {
        panic!("not an object");
    };
    members
        .into_iter()
        .find(|m| matches!(m.name(), SemanticAvailability::Available(n) if n == name))
        .expect("member")
        .value()
}

fn main() {
    let source: Arc<[u8]> = Arc::from(br#"{"a":1,"b":{"c":2}}"#.as_slice());
    // 1. parse：json.strict 无损解析，render() 与源字节逐字节一致
    let document = parse_document(source, &ProfileId::new("json.strict", 1))
        .expect("well-formed strict JSON parses");
    let json = document
        .as_json()
        .expect("a json.strict document is a JSON document");
    // 2. query：原生语义树读 `b.c`
    let c = member(member(json.root(), "b"), "c");
    // 3. edit：`b.c` 语义替换为 42（CanonicalForProfile），编辑外字节原样保留
    let mut builder = EditTransactionBuilder::new(json);
    builder.semantic_scalar(
        c.node_ref(),
        PortableValue::integer(BigInteger::from(42)),
        RepresentationPolicy::CanonicalForProfile,
    );
    let edited = json
        .commit(&builder.build())
        .expect("edit commits on a complete document")
        .document;
    // 4. render：输出 `{"a":1,"b":{"c":42}}`
    println!("{}", String::from_utf8_lossy(edited.render()));
}
