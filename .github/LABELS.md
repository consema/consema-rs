# Pull request labels

Every pull request must carry **at least one** `kind:` label — enforced by
`.github/workflows/pr-labels.yml` (viper checks.yaml pattern;
`mheap/github-action-required-labels`, mode: minimum / count: 1). The check
re-evaluates on `opened`, `synchronize`, `reopened`, `labeled` and
`unlabeled`, so adding a label flips it green without a rebase.

| Label           | Color    | Meaning                                                            |
|-----------------|----------|--------------------------------------------------------------------|
| `kind: bug`     | `d73a4a` | Fixes a bug / defect                                               |
| `kind: feature` | `0e8a16` | New capability or behavior                                         |
| `kind: docs`    | `0075ca` | Documentation-only change                                          |
| `kind: chore`   | `5319e7` | Maintenance: tooling, CI, dependencies, refactor without behavior change |
| `kind: release` | `fbca04` | Release preparation / version bump                                 |

Create the labels in a fresh checkout (or any new repository copy) with:

```
gh label create "kind: bug" --color d73a4a
gh label create "kind: feature" --color 0e8a16
gh label create "kind: docs" --color 0075ca
gh label create "kind: chore" --color 5319e7
gh label create "kind: release" --color fbca04
```

The default GitHub issue labels (bug, enhancement, documentation, ...) stay
available for issues; the `kind:` taxonomy above is the PR gate vocabulary.
