# JSON family real-project fixtures

These fixtures are non-proprietary, representative configuration documents assembled from common project shapes. They are not claimed to be byte copies of a third-party project.

- `package.json`: strict JSON package metadata, scripts, engines, dependencies, and nested tool configuration.
- `tsconfig.jsonc`: JSONC compiler configuration with line comments and trailing commas.
- `vscode-settings.jsonc`: JSONC editor settings with dotted keys, arrays, nested objects, and comments.
- `application.json5`: JSON5 service configuration with identifiers, single-quoted strings, hexadecimal and leading-point numbers, comments, and trailing commas.

The hardening suite requires exact parse/render closure for each declared profile, exact native projection, and successful finite-value canonical conversion to strict JSON.
