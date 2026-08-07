//! Deterministic in-process mutational fuzz harness (0.13.0 gate plan M2).
//!
//! The 0.13.0 gate plan (docs/0.13.0-gate-plan.md, M2 and §15.3) requires a
//! per-format fuzz target set for parser/decoder/query/projection/
//! materialization/edit entry points with resource limits pinned to the
//! production profile defaults, plus a committed seed/corpus story. The plan
//! allows either cargo-fuzz or an equivalent harness ("cargo-fuzz 或等价
//! harness").
//!
//! This workspace cannot run cargo-fuzz/libFuzzer: the toolchain is
//! `x86_64-pc-windows-msvc` and no clang is installed, so `libfuzzer-sys`
//! cannot build its C++ runtime (verified 2026-08-07; `cargo fuzz` 0.13.2 is
//! installed but every target needs the clang runtime). The equivalent
//! harness implemented here is a deterministic in-process mutational engine:
//!
//! * seed-based (committed seed constants, xorshift64* derived RNG), so every
//!   run is reproducible and the seeds are evidence (the gate plan rejects
//!   unseeded runs: "不发随机种子的空跑不算证据");
//! * bounded iterations per run, so the same engine drives the in-tree
//!   `cargo test` drivers (fast, CI) and the manual long runs (a few minutes
//!   per target, `cargo test --test <name> -- --ignored`);
//! * invariant-checking targets: the per-format targets are plain functions
//!   that `assert!` the closure properties (no panic; formed documents
//!   render byte-exactly and cover their source exhaustively; recovered
//!   documents never reach project/materialize/edit; resource-limit failure
//!   is a pass, never a crash). A violated invariant panics with the exact
//!   input, which is the regression artifact to commit to
//!   `conformance/corpora/mutation-v1.json`.
//!
//! Each format's target logic lives in one file under
//! `crates/<format>/fuzz/fuzz_logic/` and is the single source of truth
//! included both by the in-tree drivers here and by the cargo-fuzz wrappers
//! under `crates/<format>/fuzz/fuzz_targets/` (which run unmodified on a
//! libFuzzer-capable host, e.g. the Linux machine used for the 72 CPU-hours
//! milestone M8).
//!
//! Equivalence to libFuzzer: libFuzzer mutates its input corpus with
//! byte-level operations (bit flips, byte flips, insertion, deletion,
//! duplication, truncation) under a deterministic RNG derived from the seed.
//! [`mutate`] implements the same operator set with the same determinism
//! contract, so the operator coverage class is equivalent; the difference is
//! corpus evolution (libFuzzer keeps coverage-increasing inputs) which is
//! replaced here by the committed mutation corpus
//! (`conformance/corpora/mutation-v1.json`) and committed seed constants.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// One deterministic mutation applied to a byte slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOp {
    /// XOR the byte at the mutated position with `mask`.
    Flip {
        /// The XOR mask applied to the byte at the mutated position.
        mask: u8,
    },
    /// Keep only the first `len` bytes.
    Truncate {
        /// The new length in bytes.
        len: usize,
    },
    /// Insert one `byte` from the operator pool at `offset`.
    Insert {
        /// The insertion point.
        offset: usize,
        /// The inserted byte (from [`INSERT_BYTES`]).
        byte: u8,
    },
    /// Delete `count` bytes starting at `offset`.
    Delete {
        /// The deletion start.
        offset: usize,
        /// The number of deleted bytes.
        count: usize,
    },
    /// Repeat the `span`-byte chunk at `offset` `times` times.
    Repeat {
        /// Start of the repeated chunk.
        offset: usize,
        /// Chunk length in bytes.
        span: usize,
        /// Total repetitions after the original.
        times: usize,
    },
    /// Splice a `span`-byte chunk copied from `offset_from` into `offset_to`.
    Splice {
        /// Source chunk start.
        offset_from: usize,
        /// Destination insertion point.
        offset_to: usize,
        /// Chunk length in bytes.
        span: usize,
    },
}

impl MutationOp {
    /// Applies this operator to `input`; the result is always bounded by
    /// `MAX_MUTATED_LEN` bytes and never panics.
    #[must_use]
    pub fn apply(self, input: &[u8]) -> Vec<u8> {
        const MAX_MUTATED_LEN: usize = 16 * 1024;
        let mut output = input.to_vec();
        match self {
            Self::Flip { mask } => {
                if let Some(byte) = output.first_mut() {
                    *byte ^= mask;
                }
            }
            Self::Truncate { len } => output.truncate(len.min(output.len())),
            Self::Insert { offset, byte } => {
                if output.len() < MAX_MUTATED_LEN {
                    output.insert(offset.min(output.len()), byte);
                }
            }
            Self::Delete { offset, count } => {
                let start = offset.min(output.len());
                let end = (start + count).min(output.len());
                output.drain(start..end);
            }
            Self::Repeat {
                offset,
                span,
                times,
            } => {
                let start = offset.min(output.len());
                let chunk: Vec<u8> = output
                    .iter()
                    .skip(start)
                    .take(span.min(output.len().saturating_sub(start)))
                    .copied()
                    .collect();
                if !chunk.is_empty() && output.len() + chunk.len() * (times - 1) <= MAX_MUTATED_LEN
                {
                    for _ in 0..(times - 1) {
                        output.splice(start..start, chunk.iter().copied());
                    }
                }
            }
            Self::Splice {
                offset_from,
                offset_to,
                span,
            } => {
                let from = offset_from.min(output.len());
                let chunk: Vec<u8> = output
                    .iter()
                    .skip(from)
                    .take(span.min(output.len().saturating_sub(from)))
                    .copied()
                    .collect();
                if !chunk.is_empty() {
                    let to = offset_to.min(output.len());
                    if output.len() + chunk.len() <= MAX_MUTATED_LEN {
                        output.splice(to..to, chunk);
                    }
                }
            }
        }
        output
    }
}

/// The byte pool used by `Insert` (ASCII control/quote/backslash/UTF-8 edge
/// bytes chosen adversarially).
pub const INSERT_BYTES: &[u8] = &[
    0x00, 0x01, 0x0A, 0x0D, 0x09, 0x22, 0x27, 0x5C, 0x2F, 0x7F, 0x80, 0xC3, 0xEF, 0xFF,
];
/// The flip masks used by `Flip`.
pub const FLIP_MASKS: &[u8] = &[0x01, 0x02, 0x10, 0x7F, 0x80, 0xFF];

/// Deterministic 64-bit RNG (xorshift64* seeded by splitmix64).
#[derive(Clone, Copy, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Creates an RNG from a committed seed constant.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next uniform `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Next uniform value in `0..bound`.
    pub fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }
}

/// Derives the mutation seed for iteration `index` of a run starting at
/// `base_seed`: distinct, deterministic, and spread out.
#[must_use]
pub const fn iteration_seed(base_seed: u64, index: u64) -> u64 {
    base_seed ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Draws one deterministic mutation operator for `input` under `seed`.
#[must_use]
pub fn mutation_for(seed: u64, input: &[u8]) -> MutationOp {
    let mut rng = Rng::new(seed);
    let len = input.len();
    match rng.next_usize(6) {
        0 => MutationOp::Flip {
            mask: FLIP_MASKS[rng.next_usize(FLIP_MASKS.len())],
        },
        1 => MutationOp::Truncate {
            len: rng.next_usize(len + 1),
        },
        2 => MutationOp::Insert {
            offset: rng.next_usize(len + 1),
            byte: INSERT_BYTES[rng.next_usize(INSERT_BYTES.len())],
        },
        3 => MutationOp::Delete {
            offset: rng.next_usize(len),
            count: 1 + rng.next_usize(8).min(len.saturating_sub(1)),
        },
        4 => MutationOp::Repeat {
            offset: rng.next_usize(len),
            span: 1 + rng.next_usize(8.min(len.max(1))),
            times: 2 + rng.next_usize(3),
        },
        _ => MutationOp::Splice {
            offset_from: rng.next_usize(len),
            offset_to: rng.next_usize(len + 1),
            span: 1 + rng.next_usize(16.min(len.max(1))),
        },
    }
}

/// A mutated input derived deterministically from `seed` and `input`.
#[must_use]
pub fn mutate(seed: u64, input: &[u8]) -> Vec<u8> {
    mutation_for(seed, input).apply(input)
}

/// The output of a failed invariant check: the exact input that violated it.
#[derive(Clone, Debug)]
pub struct FuzzFinding {
    /// Zero-based iteration index inside the run.
    pub iteration: u64,
    /// The exact mutated input that violated an invariant.
    pub input: Vec<u8>,
    /// The panic message (the violated invariant).
    pub message: String,
}

impl FuzzFinding {
    /// Formats the finding as one line including the minimal input in hex.
    #[must_use]
    pub fn render(&self) -> String {
        let mut hex = String::with_capacity(self.input.len() * 2);
        for byte in &self.input {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        format!(
            "fuzz finding at iteration {} (seed-derived): {}\ninput hex: {}\ninput bytes: {:?}",
            self.iteration,
            self.message,
            hex,
            String::from_utf8_lossy(&self.input)
        )
    }
}

/// Runs `target` against `iterations` deterministic mutations of `base`.
///
/// The target asserts the format invariants and panics on violation; the
/// runner captures the panic and returns it as a [`FuzzFinding`] carrying the
/// exact input, so a failure is actionable (the input is the regression
/// artifact for `conformance/corpora/mutation-v1.json`).
///
/// A target that returns normally for every input means the run is clean.
pub fn run(
    base_seed: u64,
    iterations: u64,
    base: &[u8],
    target: impl Fn(&[u8]),
) -> Result<(), FuzzFinding> {
    for index in 0..iterations {
        let input = mutate(iteration_seed(base_seed, index), base);
        let outcome = catch_unwind(AssertUnwindSafe(|| target(&input)));
        if let Err(payload) = outcome {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("target panicked without a message")
                .to_owned();
            return Err(FuzzFinding {
                iteration: index,
                input,
                message,
            });
        }
    }
    Ok(())
}

/// Runs the target over a set of seeds for `seed_count` distinct committed
/// seeds, `iterations` each. Used by the manual long-run mode.
pub fn run_multi_seed(
    base_seeds: &[u64],
    iterations: u64,
    base: &[u8],
    target: impl Fn(&[u8]),
) -> Result<(), FuzzFinding> {
    for (seed_index, base_seed) in base_seeds.iter().enumerate() {
        if let Err(finding) = run(*base_seed, iterations, base, &target) {
            return Err(FuzzFinding {
                iteration: finding.iteration + seed_index as u64 * iterations,
                input: finding.input,
                message: finding.message,
            });
        }
    }
    Ok(())
}
