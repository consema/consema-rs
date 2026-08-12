# YAML real-project fixtures

These fixtures were written specifically for Consema and are covered by the
repository's MIT license. They are representative configurations, not copies
of third-party project files, and contain no credentials or deployable secrets.

- `kubernetes-workload.yaml` is a two-document Deployment and Service stream.
- `github-actions-ci.yaml` is a matrix-based GitHub Actions workflow.
- `compose-services.yaml` is a Compose-style application configuration.
- `anchor-heavy.yaml` exercises repeated aliases over mappings and sequences.

The hardening gate parses every fixture under `yaml.1.2-core@1`, requires
byte-exact unmodified rendering and complete lossless-syntax coverage, crosses
the graph through PGCE/1, and graph-materializes it back without changing
topology. Tree-shaped fixtures additionally close through PortableValue. The
anchor-heavy fixture instead proves that implicit sharing is rejected and that
explicit acyclic duplication succeeds.
