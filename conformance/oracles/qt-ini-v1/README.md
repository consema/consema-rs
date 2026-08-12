# Qt QSettings INI differential cases

These repository-owned MIT cases exercise only the portable subset explicitly
shared by `ini.portable@1` and Qt 6 `QSettings::IniFormat`. The authority is the
official Qt 6.10.2 MinGW qtbase package, built with Qt's official MinGW 13.1.0
toolchain. Both archives, the compiler executable, Qt6Core, the adapter, the
Windows build, and every invocation option are pinned in `manifest.json`.

The adapter opens an explicit file path, disables fallbacks, synchronizes once,
and emits `allKeys()` plus string values in deterministic order. Consema maps
each native section/key occurrence to Qt's `section/key` public view. Qt-only
`General` remapping, percent-encoded keys, slash hierarchy, QVariant `@` types,
write-time merging, and non-portable syntax are exclusions rather than hidden
Consema behavior.
