# INI production-shaped fixtures

These fixtures were written specifically for Consema and are covered by the
repository's MIT license. They represent common configuration shapes rather
than copies of third-party project files, and contain no credentials or
deployable secrets.

- `desktop-settings.ini` is a portable desktop-application configuration.
- `dotnet-service.ini` is a Windows-profile, .NET-style hosted service file.
- `python-tool.ini` exercises ConfigParser defaults, `:` delimiters, literal
  interpolation markers, and indented continuations.
- `legacy-mixed-newline.ini.hex` stores a byte fixture with deliberately mixed
  LF and CRLF terminators.
- `windows-cp1252.ini.hex` stores an explicit Windows-1252 fixture containing
  `é` and `€` bytes that are not valid UTF-8.

The `.hex` files are canonical lowercase hexadecimal byte containers. This
keeps non-UTF-8 bytes and mixed terminators stable across Git clients; the
fixture gate decodes them before parsing and verifies the decoded bytes
byte-for-byte. No normalization or encoding guess is allowed.

The gate requires complete formation, byte-exact unmodified rendering,
exhaustive lossless-syntax coverage, exact EntryMapping projection,
profile-canonical materialization closure, and replayable transactional edits.
