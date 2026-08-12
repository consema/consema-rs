# Pull request labels

Every pull request must carry **at least one** `kind:` label — enforced by
`.github/workflows/pr-labels.yml` (viper checks.yaml pattern;
`mheap/github-action-required-labels`, mode: minimum / count: 1). The check
re-evaluates on `opened`, `synchronize`, `reopened`, `labeled` and
`unlabeled`, so adding a label flips it green without a rebase.

The `area:` taxonomy below is applied automatically by
`.github/workflows/labeler.yml` (actions/labeler, tokio labeler pattern;
path-derived rules in `.github/labeler.yml`, `sync-labels: true`) and
complements the human-chosen `kind:` label.

| Label           | Color    | Meaning                                                            |
|-----------------|----------|--------------------------------------------------------------------|
| `kind: bug`     | `d73a4a` | Fixes a bug / defect                                               |
| `kind: feature` | `0e8a16` | New capability or behavior                                         |
| `kind: docs`    | `0075ca` | Documentation-only change                                          |
| `kind: chore`   | `5319e7` | Maintenance: tooling, CI, dependencies, refactor without behavior change |
| `kind: release` | `fbca04` | Release preparation / version bump                                 |
| `area: core`    | `d93f0b` | Implementation / authoritative content (repo source tree)          |
| `area: ci`      | `bfd4f2` | CI / tooling: `.github/**`, `scripts/**`                           |
| `area: docs`    | `c2e0c6` | Documentation: `*.md`, `docs/**`                                   |
| `needs-info`    | `fbca04` | Issues awaiting information: the stale workflow (`only-labels: needs-info`) target |

Create the labels in a fresh checkout (or any new repository copy) with:

```
gh label create "kind: bug" --color d73a4a
gh label create "kind: feature" --color 0e8a16
gh label create "kind: docs" --color 0075ca
gh label create "kind: chore" --color 5319e7
gh label create "kind: release" --color fbca04
gh label create "area: core" --color d93f0b
gh label create "area: ci" --color bfd4f2
gh label create "area: docs" --color c2e0c6
gh label create "needs-info" --color fbca04 --description "等待更多信息"
```

The default GitHub issue labels (bug, enhancement, documentation, ...) stay
available for issues; the `kind:` taxonomy above is the PR gate vocabulary.

The `needs-info` label is the stale workflow target (`only-labels: needs-info`, .github/workflows/stale.yml); it applies to issues awaiting information, never to PRs.
