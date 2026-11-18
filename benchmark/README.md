# Public benchmark contract

This directory defines the reproducible input contract for future performance
benchmarks. It is intentionally separate from the runtime library and does not
change the package API.

The benchmark runner must use synthetic, offline inputs and a fixed clock. A
transport replay returns bytes from memory; it must not contact a network. CPU
time and wall-clock time are reported separately. Cold startup, warm cache hit,
warm cache miss, and transport replay are distinct scenarios.

The [scenario catalog](../test/fixtures/benchmark-fixtures.ts) pins the trust
anchor, policy, signed inputs, clock, cache setup, transport replay, and expected
outcomes. Base64 fields hold complete DER objects. Replay responses are keyed by
endpoint and include the reference request for the same CertID. Compare the
decoded CertID across implementations if request encodings differ. Replay a
timeout as a rejected transport call. Request counts are asserted for success,
cache hits, and local rejection. Record counts on other failure paths because
adapters may start the two checks in a different order.

The [binary vectors](../test/fixtures/benchmark-vectors.ts) were generated with
OpenSSL 4.1.0 and Node 22 using an ephemeral synthetic P-256 hierarchy.
OpenSSL verified both good responses and the revoked response against the
corresponding requests. The good OCSP responses were issued on November 18,
2026 UTC and expire on November 19 UTC. The stale scenario advances the
verification clock while keeping the certificates within their validity window.
For the warm hit, prime the same instance with `primeWithJws` at the case clock,
then reset the transport counter before measuring the second signed payload.

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
