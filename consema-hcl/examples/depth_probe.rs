//! Stack-safety depth probe for the R-3 recursion budgets (plan §7.2, §11).
//!
//! Measures how deep each recursive parse dimension can go on a small-stack
//! thread before the process dies of a stack overflow. The probe builds an
//! adversarial source of `levels` nesting for one dimension, spawns a thread
//! with a caller-sized stack (2 MB default), and parses with the HCL default
//! limits plus any depth overrides, printing one result line:
//!
//! - `formed:<status>` — the document formed (Complete or Recovered);
//! - `fatal:<code>` — formation failed fatally with one `hcl.limit.*@1`
//!   code (the budget truncated the recursion before it exploded);
//! - `panic:<message>` — the thread panicked but survived.
//!
//! A stack overflow cannot be caught: it aborts the process, so the caller
//! must run each probe level in a fresh process (the probe is deliberately
//! runnable as `cargo run -p consema-hcl --example depth_probe -- <dim> N`)
//! and treat a non-zero exit as "not stack-safe at N". The default depth
//! overrides (`--expression-depth`, `--body-depth`, `--template-depth`) let
//! the probe push recursion past the frozen defaults; without them the
//! budget truncates before the overflow point, which is the safe behavior
//! the defaults must guarantee.
//!
//! Dimensions (`<dim>`):
//!
//! - `parens` — `a = ((((1))))`; the expression ladder re-enters per level.
//! - `chain` — `a = 1 + 1 + ...`; the parse loop is iterative, so only the
//!   left-deep tree drop recurses after formation.
//! - `unary` — `a = -----1`; `parse_term` recurses directly.
//! - `conditional` — `a = 1 ? 1 : 1 ? 1 : 1`; the else branch re-enters the
//!   ladder per level.
//! - `index` — `a = x[0][0]...`; each index step re-enters the ladder.
//! - `call` — `a = f(f(f(...1...)))`; each argument re-enters the ladder.
//! - `tuple` — `a = [[[[1]]]]`; each element re-enters the ladder.
//! - `object` — `a = {k = {k = 1}}`; each value re-enters the ladder.
//! - `for` — `a = [for v in [for v in [1] : v] : v]`; the collection
//!   expression re-enters the ladder.
//! - `template` — `a = "${"${"${1}"}"}"`; each interpolation re-lexes its
//!   interior on a sub-parser, the heaviest per-level frame chain.
//! - `heredoc` — `h = <<EOT\n${"${...`; the same region recursion under a
//!   heredoc template.
//! - `blocks` — nested `b0 { b1 { ... } }`; body depth via block nesting.
//!
//! Measured overflow points on a 2 MB debug-build thread (2026-08-07,
//! Windows 11, x86_64): see
//! `parser::tests::default_depth_budgets_keep_the_measured_stack_margin`.

use consema_hcl::{HclEncodingSelection, HclParseLimits, HclProfile, parse};
use std::fmt::Write as _;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dimension) = args.first() else {
        eprintln!(
            "usage: depth_probe <dimension> <levels> [--stack-mb N] [--expression-depth N] \
             [--body-depth N] [--template-depth N]"
        );
        std::process::exit(2);
    };
    let levels: usize = args
        .get(1)
        .and_then(|value| value.parse().ok())
        .expect("levels must be a usize");
    let mut stack_mb = 2usize;
    let mut expression_depth = None;
    let mut body_depth = None;
    let mut template_depth = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--stack-mb" => {
                index += 1;
                stack_mb = args[index].parse().expect("--stack-mb must be a usize");
            }
            "--expression-depth" => {
                index += 1;
                expression_depth = Some(args[index].parse().expect("usize"));
            }
            "--body-depth" => {
                index += 1;
                body_depth = Some(args[index].parse().expect("usize"));
            }
            "--template-depth" => {
                index += 1;
                template_depth = Some(args[index].parse().expect("usize"));
            }
            other => panic!("unknown argument: {other}"),
        }
        index += 1;
    }
    let source = build_source(dimension, levels);
    let limits = HclParseLimits {
        max_expression_depth: expression_depth
            .unwrap_or_else(|| HclParseLimits::default().max_expression_depth),
        max_body_depth: body_depth.unwrap_or_else(|| HclParseLimits::default().max_body_depth),
        max_template_depth: template_depth
            .unwrap_or_else(|| HclParseLimits::default().max_template_depth),
        ..HclParseLimits::default()
    };
    let thread = std::thread::Builder::new()
        .stack_size(stack_mb * 1024 * 1024)
        .spawn(move || {
            match parse(
                Arc::<[u8]>::from(source),
                HclProfile::NativeV1,
                HclEncodingSelection::ProfileDefault,
                limits,
            ) {
                Ok(document) => {
                    println!("formed:{:?}", document.status());
                    for diagnostic in document.diagnostics() {
                        println!("diagnostic:{}", diagnostic.code);
                    }
                }
                Err(failure) => {
                    let code = failure
                        .diagnostics()
                        .first()
                        .map_or("(no diagnostic)", |diagnostic| diagnostic.code.as_str());
                    println!("fatal:{code}");
                }
            }
        })
        .expect("spawning the probe thread");
    match thread.join() {
        Ok(()) => {}
        Err(panic) => {
            let message = panic
                .downcast_ref::<&str>()
                .copied()
                .map(String::from)
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic payload".to_owned());
            println!("panic:{message}");
        }
    }
}

/// Builds the adversarial source for one recursive dimension at `levels`
/// nesting. Each dimension ends in a newline so the attribute terminates.
fn build_source(dimension: &str, levels: usize) -> Vec<u8> {
    let mut source = String::new();
    match dimension {
        "parens" => {
            source.push_str("a = ");
            for _ in 0..levels {
                source.push('(');
            }
            source.push('1');
            for _ in 0..levels {
                source.push(')');
            }
        }
        "chain" => {
            source.push_str("a = 1");
            for _ in 0..levels {
                source.push_str(" + 1");
            }
        }
        "unary" => {
            source.push_str("a = ");
            for _ in 0..levels {
                source.push('-');
            }
            source.push('1');
        }
        "conditional" => {
            source.push_str("a = ");
            for _ in 0..levels {
                source.push_str("1 ? 1 : ");
            }
            source.push('1');
        }
        "index" => {
            source.push_str("a = x");
            for _ in 0..levels {
                source.push_str("[0]");
            }
        }
        "call" => {
            source.push_str("a = ");
            for _ in 0..levels {
                source.push_str("f(");
            }
            source.push('1');
            for _ in 0..levels {
                source.push(')');
            }
        }
        "tuple" => {
            source.push_str("a = ");
            for _ in 0..levels {
                source.push('[');
            }
            source.push('1');
            for _ in 0..levels {
                source.push(']');
            }
        }
        "object" => {
            source.push_str("a = ");
            for _ in 0..levels {
                source.push_str("{k = ");
            }
            source.push('1');
            for _ in 0..levels {
                source.push('}');
            }
        }
        "for" => {
            source.push_str("a = ");
            for _ in 0..levels {
                source.push_str("[for v in ");
            }
            source.push_str("[1]");
            for _ in 0..levels {
                source.push_str(" : v]");
            }
        }
        "template" => {
            // True template nesting re-enters a quoted template inside each
            // interpolation: `"${"` per level, the inner template closes
            // with `"` before the interpolation's `}` (`"}` per level), and
            // one final `"` closes the outer template.
            source.push_str("a = \"");
            for _ in 0..levels {
                source.push_str("${\"");
            }
            source.push('1');
            for _ in 0..levels {
                source.push_str("\"}");
            }
            source.push('"');
        }
        "heredoc" => {
            source.push_str("h = <<EOT\n");
            for _ in 0..levels {
                source.push_str("${\"");
            }
            source.push('1');
            for _ in 0..levels {
                source.push_str("\"}");
            }
            source.push_str("\nEOT\n");
        }
        "blocks" => {
            source.push_str("a = 1\n");
            for level in 0..levels {
                let _ = writeln!(source, "b{level} {{");
            }
            source.push_str("x = 1\n");
            for level in (0..levels).rev() {
                let _ = writeln!(source, "}}");
                let _ = writeln!(source, "// close b{level}");
            }
        }
        other => panic!("unknown dimension: {other}"),
    }
    source.push('\n');
    source.into_bytes()
}
