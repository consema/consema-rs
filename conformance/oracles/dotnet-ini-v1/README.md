# .NET IniConfigurationProvider differential cases

These repository-owned MIT cases pin the documented .NET 10
`IniConfigurationProvider` surface that overlaps `ini.python-configparser@1`:
UTF-8 text input, `#`/`;` comments, sections, `=` options, raw inline markers,
trimming, and strict duplicate rejection. The provider's flattened,
case-insensitive `section:key` mapping is an explicit comparison transform, not
Consema's native INI model.

The live replayer uses the official .NET SDK 10.0.302 ZIP and its bundled
Microsoft.AspNetCore.App 10.0.10 assembly. It restores with a repository-owned
zero-source NuGet configuration, builds with warnings as errors, loads every
case from a memory stream, and fails closed on changed packages, assemblies,
sources, runtime facts, expectations, or unrecorded inputs.

Provider layering, reload, binding, interpolation, global keys, slash comment
extensions, non-ASCII case folding, filesystem lookup, and writes are explicit
exclusions.
