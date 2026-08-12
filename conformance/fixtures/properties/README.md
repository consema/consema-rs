# Java Properties production-shaped fixtures

These fixtures were written specifically for Consema and are covered by the
repository's MIT license. They represent common configuration shapes rather
than copies of third-party project files, and contain no credentials or
deployable secrets.

- `logging.properties` is a Java Util Logging-style configuration.
- `messages.properties` is a UTF-8 Reader localization bundle.
- `build-tool.properties` is a build-tool settings file.
- `windows-paths.properties` exercises escaped Windows paths.
- `continuation-heavy.properties` exercises logical values assembled from
  several natural lines and an even trailing-backslash case.
- `latin1-resource.properties.hex` stores non-UTF-8 Latin-1 resource bytes.
- `utf16-edge.properties` stores a supplementary scalar and legal unpaired
  Java UTF-16 code units through `\uXXXX` escapes.

The `.hex` file is a canonical lowercase hexadecimal byte container. The
fixture gate decodes it before parsing and verifies the decoded bytes exactly.
The gate requires complete formation, byte-exact unmodified rendering,
exhaustive lossless-syntax coverage, explicit projection behavior for unpaired
surrogates, canonical materialization closure for scalar fixtures, and
replayable transactional edits.
