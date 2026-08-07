//! Adversarial HCL closure properties for the 0.11.0 release gate.

use consema_document::{FatalFormationFailure, FormationStatus};
use consema_hcl::{HclEncodingSelection, HclParseLimits, HclProfile, parse};
use std::sync::Arc;

fn parse_hcl(
    source: &[u8],
    limits: HclParseLimits,
) -> Result<consema_hcl::Document, FatalFormationFailure> {
    parse(
        Arc::<[u8]>::from(source.to_vec()),
        HclProfile::NativeV1,
        HclEncodingSelection::ProfileDefault,
        limits,
    )
}

/// Every formed document, complete or recovered, must render byte-exactly,
/// cover its source exhaustively, and keep kinds parallel to pieces; nothing
/// may panic.
fn assert_parse_closure(source: &[u8], limits: HclParseLimits) {
    if let Ok(document) = parse_hcl(source, limits) {
        assert_eq!(document.render(), source);
        let index = document.lossless_structural_index();
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, source.len());
        assert_eq!(
            document.lossless_syntax_kinds().len(),
            index.pieces().len(),
            "kinds stay parallel to pieces"
        );
    }
}

#[test]
fn malformed_hcl_never_forms_partial_documents() {
    let malformed: &[&[u8]] = &[
        b"=",
        b"a =",
        b"a = 1 +",
        b"a = (1",
        b"a = [1, 2",
        b"a = {x = 1",
        b"a = \"unterminated",
        b"a = \"${1 +\"",
        b"a = <<EOT\ncontent\n",
        b"a = 1 @ 2\n",
        b"a = 1 /\n",
        b"a = 1 /* unterminated",
        b"a = \"bad \\q\"\n",
        b"a = 0x1F\n",
        b"a = +1\n",
        b"_foo = 1\n",
        b"a = foo.0\n",
        b"a = foo::bar()\n",
        b"a = 1\rb = 2\n",
        b"\xEF\xBB\xBFa = 1\n",
        b"a = 1\n\xEF\xBB\xBFb = 2\n",
        b"b \"x\"\n",
        b"b {\n",
        b"a = 1\na = 2\n",
        b"\xff",
        b"a = \xff\n",
    ];
    for source in malformed {
        if let Ok(document) = parse_hcl(source, HclParseLimits::default()) {
            assert_eq!(
                document.status(),
                FormationStatus::Recovered,
                "malformed input must recover, never complete: {source:?}"
            );
            assert!(
                !document.diagnostics().is_empty(),
                "recovered document must publish diagnostics: {source:?}"
            );
        }
    }
}

#[test]
fn mutation_and_truncation_never_panic_or_fabricate() {
    let seeds: &[&[u8]] = &[
        b"region = \"us-east-1\"\nserver \"web\" {\n  port = 8080\n}\ncount = 3\n",
        b"# comment\na = \"${x}\"\nb = [1, 2, {k = \"v\"}]\nc = <<EOT\nline ${y}\nEOT\n",
        "a = \"中文 & 文\"\nb = 1e3\nc = true ? \"yes\" : \"no\"\n".as_bytes(),
        b"\xEF\xBB\xBFa = 1\n",
        b"a = \"bad \\q\"\nb = \"\\u0041\"\n",
        b"terraform {\n  required_version = \">= 1.5\"\n}\n\nvariable \"region\" {\n  type    = string\n  default = \"us-east-1\"\n}\n",
        b"a = \"%{ if x }${x}%{ endif }\"\nb = [for v in x : v if v > 1]\n",
        b"h = <<-EOT\n  indented\n  EOT\ni = foo.*.bar\nj = foo[*].baz\n",
    ];
    for seed in seeds {
        for length in 0..seed.len() {
            assert_parse_closure(&seed[..length], HclParseLimits::default());
        }
        for index in 0..seed.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = seed.to_vec();
                mutated[index] ^= mask;
                assert_parse_closure(&mutated, HclParseLimits::default());
            }
        }
    }
}

#[test]
fn adversarial_nesting_never_panics_or_overflow_the_stack() {
    use std::fmt::Write as _;
    // Adversarial depth beyond any production configuration: 2,000 levels.
    // The parse must never panic: the expression/body depth budget must
    // truncate before the recursion overflows the stack.
    let mut deep_parens = String::from("a = ");
    for _ in 0..2_000 {
        deep_parens.push('(');
    }
    deep_parens.push('1');
    for _ in 0..2_000 {
        deep_parens.push(')');
    }
    deep_parens.push('\n');

    let mut deep_chain = String::from("a = 1");
    for _ in 0..2_000 {
        deep_chain.push_str(" + 1");
    }
    deep_chain.push('\n');

    let mut deep_blocks = String::from("a = 1\n");
    for index in 0..2_000 {
        let _ = writeln!(deep_blocks, "b{index} {{");
    }
    deep_blocks.push_str("x = 1\n");
    for index in (0..2_000).rev() {
        let _ = writeln!(deep_blocks, "}}");
        let _ = writeln!(deep_blocks, "// close b{index}");
    }

    let mut deep_templates = String::from("a = \"");
    for _ in 0..2_000 {
        deep_templates.push_str("${");
    }
    deep_templates.push('1');
    for _ in 0..2_000 {
        deep_templates.push('}');
    }
    deep_templates.push_str("\"\n");

    // A stack-safe configured budget truncates before the recursion
    // deepens: a tight expression budget makes deep nesting a fatal
    // `hcl.limit.expression-depth@1` outcome, never a panic.
    let tight = HclParseLimits {
        max_expression_depth: 24,
        ..HclParseLimits::default()
    };
    for source in [deep_parens, deep_chain] {
        let Err(failure) = parse_hcl(source.as_bytes(), tight) else {
            panic!("deep nesting must be truncated by the expression budget");
        };
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|d| d.code == "hcl.limit.expression-depth@1"),
            "deep nesting must hit the expression-depth limit"
        );
    }
    // Body nesting truncates under the body-depth budget.
    let tight_body = HclParseLimits {
        max_body_depth: 8,
        ..HclParseLimits::default()
    };
    let Err(failure) = parse_hcl(deep_blocks.as_bytes(), tight_body) else {
        panic!("deep block nesting must be truncated by the body-depth budget");
    };
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|d| d.code == "hcl.limit.body-depth@1"),
        "deep block nesting must hit the body-depth limit"
    );
    // Deeply nested template interpolations must never panic under the
    // default budgets.
    let document = parse_hcl(deep_templates.as_bytes(), HclParseLimits::default())
        .expect("deep template nesting must not panic");
    assert_eq!(document.render(), deep_templates.as_bytes());
}

#[test]
fn default_limits_truncate_deep_nesting_on_a_small_stack_thread() {
    use std::fmt::Write as _;
    // The R-3 defect: the frozen default budgets, not only configured ones,
    // must truncate deep recursion before the stack explodes — even on a
    // 2 MB thread. Each adversarial input is 2,000 levels and must fail
    // with the documented `hcl.limit.*@1` code, never a panic and never a
    // stack overflow (the measured overflow points are documented in the
    // crate's `depth_probe` example and its parser tests).
    let mut deep_parens = String::from("a = ");
    for _ in 0..2_000 {
        deep_parens.push('(');
    }
    deep_parens.push('1');
    for _ in 0..2_000 {
        deep_parens.push(')');
    }
    deep_parens.push('\n');

    let mut deep_chain = String::from("a = 1");
    for _ in 0..2_000 {
        deep_chain.push_str(" + 1");
    }
    deep_chain.push('\n');

    let mut deep_blocks = String::from("a = 1\n");
    for index in 0..2_000 {
        let _ = writeln!(deep_blocks, "b{index} {{");
    }
    deep_blocks.push_str("x = 1\n");
    for index in (0..2_000).rev() {
        let _ = writeln!(deep_blocks, "}}");
        let _ = writeln!(deep_blocks, "// close b{index}");
    }

    // True template nesting re-enters a quoted template inside each
    // interpolation; the frozen lexical budget fires first beyond ~127
    // levels, while shallower nesting truncates in the parser.
    let mut deep_templates = String::from("a = \"");
    for _ in 0..2_000 {
        deep_templates.push_str("${\"");
    }
    deep_templates.push('1');
    for _ in 0..2_000 {
        deep_templates.push_str("\"}");
    }
    deep_templates.push('"');
    deep_templates.push('\n');

    let thread = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            for (source, code) in [
                (deep_parens.as_bytes(), "hcl.limit.expression-depth@1"),
                (deep_chain.as_bytes(), "hcl.limit.expression-depth@1"),
                (deep_blocks.as_bytes(), "hcl.limit.body-depth@1"),
                (deep_templates.as_bytes(), "hcl.limit.template-depth@1"),
            ] {
                let Err(failure) = parse_hcl(source, HclParseLimits::default()) else {
                    panic!("deep nesting must be truncated by the default budgets");
                };
                assert!(
                    failure.diagnostics().iter().any(|d| d.code == code),
                    "deep nesting must hit the {code} limit"
                );
            }
        })
        .expect("spawning the small-stack thread");
    thread
        .join()
        .expect("the small-stack thread must not panic");
}

#[test]
fn hcl_parse_limits_reject_before_publishing_a_document() {
    let cases: Vec<(Vec<u8>, HclParseLimits)> = vec![
        (
            b"a = 1\n".to_vec(),
            HclParseLimits {
                common: consema_document::ParseLimits {
                    max_source_bytes: 4,
                    ..consema_document::ParseLimits::default()
                },
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = (((1)))\n".to_vec(),
            HclParseLimits {
                max_expression_depth: 3,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = 1 + 1 + 1 + 1 + 1\n".to_vec(),
            HclParseLimits {
                max_expression_depth: 3,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = 1\nb {\nc {\nd = 1\n}\n}\n".to_vec(),
            HclParseLimits {
                max_body_depth: 2,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = 1\nb = 2\nc = 3\n".to_vec(),
            HclParseLimits {
                max_attribute_count: 2,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a {\n}\nb {\n}\n".to_vec(),
            HclParseLimits {
                max_block_count: 1,
                ..HclParseLimits::default()
            },
        ),
        (
            b"b \"x\" \"y\" {\n}\n".to_vec(),
            HclParseLimits {
                max_label_count: 1,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = 1e10\n".to_vec(),
            HclParseLimits {
                max_number_digits: 5,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = [1, 2, 3]\n".to_vec(),
            HclParseLimits {
                max_tuple_elements: 2,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = {x = 1, y = 2, z = 3}\n".to_vec(),
            HclParseLimits {
                max_object_entries: 2,
                ..HclParseLimits::default()
            },
        ),
        (
            b"a = \"xxxxxxxxxxxxxxxxxxxxxxxxxx\"\n".to_vec(),
            HclParseLimits {
                max_template_len: 8,
                ..HclParseLimits::default()
            },
        ),
        (
            b"h = <<E\none\ntwo\nthree\nE\n".to_vec(),
            HclParseLimits {
                max_heredoc_bytes: 12,
                ..HclParseLimits::default()
            },
        ),
    ];
    for (source, limits) in cases {
        assert!(
            parse_hcl(&source, limits).is_err(),
            "bounded HCL parse unexpectedly formed a document: {:?}",
            String::from_utf8_lossy(&source)
        );
    }
}

#[test]
fn recovered_documents_keep_exhaustive_coverage_and_diagnostics() {
    let seeds: &[&[u8]] = &[
        b"a = 1\na = 2\nb = 3\n",
        b"a = \"unterminated",
        b"a = <<EOT\ncontent\n",
        b"\xEF\xBB\xBFa = 1\n",
        b"a = 1\rb = 2\n",
        b"a = 1 +\nb = 2\n",
        b"a = 1 /* unterminated",
    ];
    for seed in seeds {
        let document = parse_hcl(seed, HclParseLimits::default()).expect("forms");
        assert_eq!(document.status(), FormationStatus::Recovered);
        assert_eq!(document.render(), *seed);
        assert!(
            !document.diagnostics().is_empty(),
            "recovery always publishes diagnostics: {:?}",
            String::from_utf8_lossy(seed)
        );
        let index = document.lossless_structural_index();
        let covered: usize = index.pieces().iter().map(|piece| piece.span().len()).sum();
        assert_eq!(covered, seed.len());
    }
}

#[test]
fn published_hcl_vector_suite_is_conformant() {
    let report = consema_conformance::run_hcl_v1();
    assert!(report.is_conformant(), "{report:#?}");
    assert_eq!(report.passed.len(), 57);
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn published_types_are_send_and_sync() {
    assert_send_sync::<consema_hcl::Document>();
    assert_send_sync::<consema_hcl::HclDocument>();
    assert_send_sync::<consema_hcl::EditTransaction>();
    assert_send_sync::<consema_hcl::EditCommit>();
    assert_send_sync::<consema_hcl::ProjectionRequest>();
    assert_send_sync::<consema_hcl::HclParseLimits>();
}
