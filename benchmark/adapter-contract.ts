export type BenchmarkOutcome = "accept" | "reject" | "transport-error";

export type BenchmarkFixtureKind = "jws" | "ocsp";

export type BenchmarkCacheState = "cold" | "warm-hit" | "warm-miss" | "warm-expired";

export type BenchmarkPolicy = Readonly<{
  application: string;
  environment: string;
  algorithm: string;
  trustedRootsBase64: readonly string[];
}>;

export type BenchmarkReplayEntry = Readonly<{
  url: string;
  requestBase64: string;
  responseBase64?: string;
  error?: string;
  delayMs?: number;
}>;

export type BenchmarkRequestInterval = Readonly<{
  url: string;
  startedAtMs: number;
  endedAtMs: number;
  durationMs: number;
}>;

export type BenchmarkTransport = Readonly<{
  request(url: string, request: Uint8Array): Promise<Uint8Array>;
  readonly requestCount: number;
  readonly requestIntervals: readonly BenchmarkRequestInterval[];
}>;

export type BenchmarkAdapterContext = Readonly<{
  policy: BenchmarkPolicy;
  clockMs: number;
  transport: BenchmarkTransport;
  ocspRequests: readonly Readonly<{
    url: string;
    request: Uint8Array;
  }>[];
}>;

export type BenchmarkVerificationInput = Readonly<{
  jws: string;
  clockMs: number;
}>;

export type BenchmarkVerificationResult = Readonly<{
  outcome: BenchmarkOutcome;
  reason?: string;
}>;

export type BenchmarkFixture = Readonly<{
  id: string;
  kind: BenchmarkFixtureKind;
  jws: string;
  clockMs: number;
  mode: "online";
  cacheState: BenchmarkCacheState;
  expectation: BenchmarkOutcome;
  reason?: string;
  expectedRequests?: number;
  primeWithJws?: string;
  primeClockMs?: number;
  provenance: "synthetic-v1";
  transport: readonly BenchmarkReplayEntry[];
}>;

export type BenchmarkVerifier = Readonly<{
  verify(input: BenchmarkVerificationInput): Promise<BenchmarkVerificationResult>;
}>;

export type BenchmarkAdapter = Readonly<{
  name: string;
  version: string;
  capabilities: readonly BenchmarkFixtureKind[];
  supports?(fixture: BenchmarkFixture): boolean;
  create(context: BenchmarkAdapterContext): BenchmarkVerifier | Promise<BenchmarkVerifier>;
}>;

export type BenchmarkAdapterModule = Readonly<{
  adapter?: BenchmarkAdapter;
  createAdapter?: () => BenchmarkAdapter | Promise<BenchmarkAdapter>;
}>;
