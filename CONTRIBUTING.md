# Contributing

Contributions are welcome, from documentation fixes to changes in the
verification core. Please keep discussions and pull requests focused,
respectful, and easy to review.

## Development workflow

This is an ESM-only TypeScript library for Node.js 22+. Use Yarn Berry from
the repository root:

```sh
corepack enable
yarn install --immutable
```

Do not use `npm install` for development. The repository is configured for
Yarn 4 and Plug'n'Play.

The main directories are:

- `source/` — runtime library implementation;
- `test/` — Vitest unit and integration tests;
- `benchmark/` — public synthetic offline benchmarks;
- `scripts/` — release, benchmark, and local runtime helpers;
- `.github/workflows/` — CI checks and benchmark jobs.

## Making changes

- Keep implementation code in `source/` and add or update Vitest tests in
  `test/` for behavior changes.
- Keep the public API deliberate: export new public symbols from
  `source/index.ts` only when the contract is stable and provider-neutral.
- Use Zod for runtime validation of external input.
- Keep CLI and process-I/O code in thin scripts; reusable behavior belongs in
  library modules.
- Do not add CommonJS compatibility or a bundler without an explicit design
  decision. The package is ESM-only.
- Do not add Prettier. Formatting is handled by `oxfmt`; linting uses Biome
  and oxlint.

Research notes, local compatibility investigations, provider-specific data,
and benchmark reports involving private checkouts belong under the locally
ignored `docs/internal/` directory. Public benchmark fixtures must be
synthetic, offline, reproducible, and free of secrets, private keys, user
payloads, and local checkout paths.

## Local checks

Run the focused check that matches your change while iterating:

```sh
yarn run lint
yarn run typecheck
yarn run test
yarn run test:smoke:apple
yarn run deps:lint
yarn run security:lint
```

Install Semgrep or `uv` before running the security check. If Semgrep is
unavailable on PATH, the script runs the pinned version through `uvx`.

Before handoff, run the complete release check:

```sh
yarn run release:check
```

This runs coverage, dependency and security checks, builds `dist/`, and
performs a publish dry run. It also installs the generated tarball in a
temporary consumer and checks ESM import and dynamic import from CommonJS.
Yarn may need registry access to install the tarball's runtime dependencies.

## Benchmarks and Worker startup

The public benchmark is synthetic and offline. CPU and wall time are measured
separately; cold verification, cache miss, cache hit, and expired-cache cases
are distinct:

```sh
yarn run benchmark:ci
yarn run benchmark:codec
```

To build the library and run the smoke test in `workerd` through Miniflare:

```sh
yarn run workerd:smoke
```

The probe records runtime readiness before the first handler invocation, then
verifies a signed JWS with OCSP responses replayed from memory. Its startup and
request measurements are wall time.

In GitHub Actions, open the workflow run's **Summary** for the Node benchmark
tables. Under **Artifacts**, `benchmark-node-22.x` and `benchmark-node-24.x`
contain the Markdown report and raw JSON. The Worker wall-time results are in
the separate `workerd-smoke` artifact. The benchmark jobs run independently of
the test matrix. For comparisons, use the same machine and Node version, and
record the sample count and commit. See the [benchmark guide](benchmark/README.md)
for the reference adapter and measurement details.

## Pull requests

Before opening a pull request:

- add tests for new behavior and negative/security cases where relevant;
- update public documentation when the API or runtime contract changes;
- run `yarn run release:check`;
- inspect `git diff` and confirm that no local `docs/internal/` artifacts,
  secrets, generated output, or unrelated changes are included;
- describe benchmark conditions and raw JSON locations when performance is
  part of the change.

Use small pull requests with a clear title. Conventional Commit-style titles
are preferred, for example `feat: add OCSP policy`, `fix: reject stale
responses`, `test: cover BER fragments`, or `docs: explain the verifier core`.
