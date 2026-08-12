# XML real-configuration fixtures

These fixtures were written specifically for Consema and are covered by the
repository's MIT license. They are representative configurations, not copies
of third-party project files, and contain no credentials or deployable
secrets.

- `maven-pom.xml` is a Maven-style build descriptor with a namespaced root,
  namespaced elements, attributes, comments, and an internal entity.
- `spring-application.xml` is a Spring-style bean application context with a
  default namespace, attributes, mixed content, and a namespaced bean.
- `logback.xml` is a logging configuration with a default namespace, appender
  elements, nested properties, and a comment.
- `app-server-config.xml` is an application-server style descriptor with
  declared namespaces, prefixed elements and attributes, and CDATA.
- `namespaced-service.xml` exercises multiple namespace prefixes, prefixed
  attributes, mixed content order, and a processing instruction.

The encoding corpus gate (`crates/consema-conformance/tests/xml_encoding_corpus.rs`)
covers BOM/declaration conflicts, UTF-16LE/BE round trips, BOM-less UTF-16
rejection under the frozen default-UTF-8 contract, non-BMP names and content,
invalid sequences, and raw/decoded span closure.

The hardening gate parses every fixture under `xml.1.0-safe@1`, requires
byte-exact unmodified rendering, complete lossless-syntax coverage, exact
`xml.element-tree@1` projection, and a canonical materialization round trip
whose reparsed projection equals the first projection exactly.
