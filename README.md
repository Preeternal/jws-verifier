# `jws-verifier`

[![npm version](https://img.shields.io/npm/v/jws-verifier.svg)](https://www.npmjs.com/package/jws-verifier)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

TypeScript library for secure JWS verification, X.509 certificate chain validation, and OCSP revocation checking

## Install

```bash
yarn add jws-verifier
```

## Usage

```ts
import { formatValue } from "jws-verifier";

const output = formatValue({ ready: true });
```

## Development

Lint, format, type-check, dependency and security policy checks, and tests are
wired into a single command:

```bash
yarn run check         # lint + dep/security checks + typecheck + coverage
yarn run test          # run tests
yarn run setup:editor  # generate local Yarn PnP SDKs for VS Code
yarn run build         # build to dist/
yarn run release:check # package validation + publish dry run
```

`yarn run security:lint` prefers `semgrep` on PATH and otherwise runs the pinned `uvx semgrep@1.165.0` scan.

## License

[MIT](LICENSE) © Preeternal.
