# Public benchmark contract

This directory contains the reproducible input contract and runner for
performance benchmarks. It is intentionally separate from the runtime library
and does not change the package API.

Run the local reference adapter with:

```bash
yarn benchmark
yarn benchmark -- --mode warm --fixture jws.synthetic.valid-warm-hit
yarn benchmark -- --mode cold --samples 30 --json > /tmp/jws-benchmark.json
yarn benchmark -- --adapter ./path/to/candidate.mjs --baseline ./benchmark/reference-adapter.mjs
yarn benchmark:ci
yarn benchmark:codec
```

The default adapter is a deliberately small native-crypto reference. It
validates the synthetic JWS and certificate chain, replays the OCSP requests
from memory, and supports only `kind: "jws"`. OCSP response semantics are
intentionally not claimed by this adapter; an implementation that supports
them is supplied with the same `BenchmarkAdapter` contract in
`adapter-contract.ts`. Unsupported fixture kinds are reported as skipped, not
silently treated as successful measurements.

An adapter module exports either `adapter` or `createAdapter`. Its `create`
method receives the fixed policy, clock, replay transport, and canonical
synthetic OCSP requests. It returns a verifier with `verify`, which reports
`accept`, `reject`, or `transport-error`. The runner checks the declared
outcome and request count for every measured sample.

The benchmark runner must use synthetic, offline inputs and a fixed clock. A
transport replay returns bytes from memory; it must not contact a network. CPU
time and wall-clock time are reported separately. Cold startup, warm cache hit,
warm cache miss, and transport replay are distinct scenarios.

The [scenario catalog](../test/fixtures/benchmark-fixtures.ts) pins the trust
anchor, policy, signed inputs, clock, cache setup, transport replay, and expected
outcomes. Base64 fields hold complete DER objects. Replay matches the endpoint
and CertID regardless of request order, including fixtures with omitted or
explicit NULL hash algorithm parameters. It counts all attempts and records
unexpected or duplicate requests separately. A fixture can specify an expected
request count and rejection reason. A timeout is a rejected transport call.

The [binary vectors](../test/fixtures/benchmark-vectors.ts) were generated with
OpenSSL 4.1.0 and Node 22 using an ephemeral synthetic P-256 hierarchy.
OpenSSL verified both good responses and the revoked response against the
corresponding requests. The good OCSP responses were issued on November 18,
2026 UTC and expire on November 19 UTC. The stale scenario advances the
verification clock while keeping the certificates within their validity window.
For the warm hit, prime the same instance with `primeWithJws` at the case clock,
then reset the transport counter before measuring the second signed payload.
An expired-cache fixture primes at `primeClockMs` and verifies later while
the cached responses would still be fresh, so it also checks the configured TTL.

Pass `--suite <path>` to use a local module that exports `benchmarkFixtures`
and `benchmarkPolicy`. Keep private suites and adapters outside the public
benchmark files.

The vectors are intended for the generic certificate profile. A provider-specific
adapter may require a separate chain and application policy.

Public fixtures must be synthetic and contain no production tokens, user data,
private keys, vendor checkout paths, or network dependency. Any external
fixture requires a separate license and redistribution review before it is
added here.

## Measurement rules

- Run on one Node.js version and one machine for a comparison series.
- Measure `process.cpuUsage()` and monotonic wall time independently.
- Measure import/initialization separately from the first verification.
- Run cold scenarios in fresh processes and warm scenarios after an explicit
  warm-up.
- Replay the same policy, clock, cache state, and transport response for every
  implementation.
- Report raw samples, median, p95, absolute times, and the baseline/candidate
  ratio. Do not use a warm-cache result as a cold-start claim.

Cold samples include separate CPU and wall measurements for adapter load,
verifier creation, and first verification in a fresh Node process. Process
launch is outside those measurements. Cold mode selects fixtures that require
no priming. Warm mode runs `--warmup` operations before sampling and records
per-operation times over batches of `--batch` operations. Verifier construction
and cache priming are outside the timed batch. The report retains per-operation
outcomes and request counts alongside the timing for each sample.

`--baseline` alternates adapter order between samples in each scenario. The
report shows median and p95 ratios for CPU and wall time (`baseline / candidate`).
Failed series are excluded from ratios and cause a nonzero exit status.

`yarn benchmark:codec` measures X.509 chain preparation with preloaded roots,
OCSP request encoding and response parsing, and BER receipt extraction.
It validates each operation before timing and records CPU and wall samples.
The receipt input is a synthetic CMS structure with an arbitrary ID and
fragmented OCTET STRINGs.

`yarn benchmark:ci` runs the built verifier on the public synthetic scenarios.
It also reports ratios on shared, validated scenarios against the native-crypto
reference. The reference replays OCSP without validating responses and creates
X.509 objects even on cache hits, so those ratios reflect the specific work each
implementation performs. CI stores the raw JSON and a Markdown summary for each
Node.js version.
