# Dependency-topological order of the workspace's publishable crates.
#
# Consumed by .github/workflows/release.yml (publish loop and final
# crates.io verification) via `cargo metadata --no-deps | jq -f this`.
#
# Why: `cargo publish -p <crate>` requires every intra-workspace dependency
# of <crate> to already exist on crates.io, so the publish order must be a
# topological order of the workspace dependency graph. An alphabetical sort
# is not one: the consema facade depends on all 13 sibling crates, so an
# alphabetical first pick would fail its very first publish. Wave-4 R10 (no
# hand-maintained crate list) is preserved: the crate SET comes from cargo
# metadata (publish == null), and the ORDER is computed from the same
# metadata, so a future 15th publishable crate is inserted automatically at
# the position its dependencies allow.
#
# Algorithm: Kahn's algorithm over the intra-workspace edges (cargo metadata
# dependency entries with a `.path` field — a registry dependency is never a
# workspace crate; `.package // .name` handles renamed dependencies). Among
# the simultaneously-ready crates the alphabetically first is picked, which
# makes the output deterministic and reproducible. On a dependency cycle, or
# an edge to a crate outside the publishable set, jq aborts (non-zero exit,
# zero output) naming the stuck crates — the release loop must never guess an
# order.
#
# Rehearsal evidence (wave-5, 2026-08-15): against the real
# `cargo metadata --no-deps --locked` output the filter emits exactly the 14
# publishable crates with consema-core first (it is the unique leaf; the
# verify-tag resume probe relies on this) and consema last; all 38
# intra-workspace edges precede their crate; two runs are byte-identical;
# synthetic two-crate cycle and publish-excluded-edge inputs both abort.
# Local runs: `cargo metadata --no-deps --format-version 1 --locked |
# jq -r -f scripts/publish-order.jq`.
.packages as $pkgs
| ($pkgs | map(select(.publish == null) | .name)) as $pub
| ($pkgs
    | map({ key: .name, value: [.dependencies[] | select(.path != null) | (.package // .name)] })
    | from_entries) as $deps
| { names: $pub, deps: $deps, out: [] }
| until(
    (.names | length) == 0;
    . as $st
    | ($st.names | map(select(($st.deps[.] // []) | length == 0))) as $ready
    | if ($ready | length) == 0 then
        error("dependency cycle or edge to a crate outside the publishable set among: " + ($st.names | join(", ")))
      else
        ($ready | sort)[0] as $pick
        | {
            names: ($st.names | map(select(. != $pick))),
            deps: ($st.deps | map_values(map(select(. != $pick)))),
            out: ($st.out + [$pick])
          }
      end)
| .out[]
