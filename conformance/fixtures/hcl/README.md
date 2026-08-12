# HCL real-configuration fixtures

These fixtures were written specifically for Consema and are covered by the
repository's MIT license. They are representative configurations, not copies
of third-party project files, and contain no credentials or deployable
secrets.

- `tf/main.tf` is a Terraform-like module configuration with a `terraform`
  block, provider, variable declarations, locals, a resource with a heredoc
  `user_data`, a module reference, an output, and a data source.
- `tf/network.tf` is a Terraform-like network configuration exercising
  `count`, `for_each`, splat traversals, conditional expressions, nested
  block bodies, and for-expressions.
- `tf/variables.tf` is a Terraform-like variable declaration file with
  typed defaults, a validation block, and map/list defaults.
- `tf/packer.pkr.hcl` is a Packer-style build configuration with a plugin
  block, an `amazon-ebs` source, filter blocks, and build provisioners.
- `tf/nomad.hcl` is a Nomad-style job specification with job, group,
  network, task, config, env, resources, and service blocks.
- `tf/vault.hcl` is a Vault-style server configuration with storage,
  listener, and seal blocks plus top-level attributes.
- `tfvars/terraform.tfvars` and `tfvars/prod.tfvars` are production-shaped
  `.tfvars` documents: attributes only, with objects, tuples, heredocs, and
  both ASCII and hyphenated names.

The fixture gate (`crates/consema-conformance/tests/hcl_fixtures.rs`) parses
every fixture under its profile, requires byte-exact unmodified rendering,
complete lossless-syntax coverage, an `hcl.projection.body@1` projection
under the explicit `ProjectExpression` policy (production configurations
contain references and for-expressions, which are derived expressions by
RFC 0014 §8.1), a canonical materialization round trip under the fixture's
profile, and a reparse whose re-projection equals the first projection
exactly (a materialization fixed point).

The differential oracle
(`conformance/oracles/hcl-go-v1/` driven by `scripts/run-hcl-go-oracle.ps1`)
runs the same fixture set against the pinned Go `hashicorp/hcl` parser and
compares parse accept/reject outcomes only (RFC 0014 §12).
