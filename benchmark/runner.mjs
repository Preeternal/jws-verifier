import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import process, {
  argv,
  cpuUsage,
  cwd,
  env,
  execPath,
  exit,
  stderr,
  stdout,
  version,
} from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ocspRequestKey } from "./ocsp-replay.mjs";

const runnerPath = fileURLToPath(import.meta.url);
const fixtureModuleUrl = new URL("../test/fixtures/benchmark-fixtures.ts", import.meta.url);
const defaultAdapterUrl = new URL("./reference-adapter.mjs", import.meta.url);
const defaultOptions = {
  adapter: defaultAdapterUrl,
  baseline: undefined,
  fixtureIds: [],
  mode: "all",
  samples: 15,
  warmup: 3,
  batch: 20,
  child: false,
};

const toMicroseconds = (milliseconds) => Math.round(milliseconds * 1000);
const cpuMicroseconds = (before, after) => after.user + after.system - before.user - before.system;
const median = (values) => {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length ? (sorted[middle] + sorted[Math.floor((sorted.length - 1) / 2)]) / 2 : 0;
};
const percentile95 = (values) => {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)] ?? 0;
};

export const summarizeSamples = (samples) => ({
  count: samples.length,
  cpuMicrosMedian: median(samples.map(({ cpuMicros }) => cpuMicros)),
  cpuMicrosP95: percentile95(samples.map(({ cpuMicros }) => cpuMicros)),
  wallMicrosMedian: median(samples.map(({ wallMicros }) => wallMicros)),
  wallMicrosP95: percentile95(samples.map(({ wallMicros }) => wallMicros)),
  cpuMicrosRange: [
    Math.min(...samples.map(({ cpuMicros }) => cpuMicros)),
    Math.max(...samples.map(({ cpuMicros }) => cpuMicros)),
  ],
  wallMicrosRange: [
    Math.min(...samples.map(({ wallMicros }) => wallMicros)),
    Math.max(...samples.map(({ wallMicros }) => wallMicros)),
  ],
});

const parseInteger = (value, option) => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${option} must be a positive integer`);
  }
  return parsed;
};

export const parseArgs = (values) => {
  const options = { ...defaultOptions, fixtureIds: [] };
  const normalizedValues = values[0] === "--" ? values.slice(1) : values;
  for (let index = 0; index < normalizedValues.length; index += 1) {
    const value = normalizedValues[index];
    if (value === "--adapter") {
      options.adapter = new URL(normalizedValues[++index], pathToFileURL(`${cwd()}/`));
    } else if (value === "--baseline") {
      options.baseline = new URL(normalizedValues[++index], pathToFileURL(`${cwd()}/`));
    } else if (value === "--suite") {
      options.suite = new URL(normalizedValues[++index], pathToFileURL(`${cwd()}/`));
    } else if (value === "--fixture") {
      options.fixtureIds.push(normalizedValues[++index]);
    } else if (value === "--mode") {
      options.mode = normalizedValues[++index];
      if (!["all", "warm", "cold"].includes(options.mode)) {
        throw new Error("--mode must be all, warm, or cold");
      }
    } else if (value === "--samples") {
      options.samples = parseInteger(normalizedValues[++index], "--samples");
    } else if (value === "--warmup") {
      options.warmup = parseInteger(normalizedValues[++index], "--warmup");
    } else if (value === "--batch") {
      options.batch = parseInteger(normalizedValues[++index], "--batch");
    } else if (value === "--json") {
      options.json = true;
    } else if (value === "--child") {
      options.child = true;
    } else if (value === "--help") {
      options.help = true;
    } else {
      throw new Error(`Unknown option: ${value}`);
    }
  }
  return options;
};

const loadAdapter = async (url) => {
  const module = await import(url.href);
  if (module.adapter) return module.adapter;
  if (typeof module.createAdapter === "function") return module.createAdapter();
  throw new Error("Adapter module must export adapter or createAdapter");
};

const loadFixtures = async (url = fixtureModuleUrl) => {
  const module = await import(url.href);
  return module;
};
const createOcspReplay = (entries) => createReplayTransport(entries, ocspRequestKey);

export const createReplayTransport = (
  entries,
  normalizeRequest = (bytes) => Buffer.from(bytes).toString("base64"),
) => {
  let requestCount = 0;
  let mismatchCount = 0;
  let requestIntervals = [];
  const used = new Set();
  const replay = entries.map((entry) => ({
    ...entry,
    key: normalizeRequest(Buffer.from(entry.requestBase64, "base64")),
    response: Buffer.from(entry.responseBase64 ?? "", "base64"),
  }));

  return {
    get requestCount() {
      return requestCount;
    },
    get mismatchCount() {
      return mismatchCount;
    },
    get requestIntervals() {
      return requestIntervals.map((interval) => ({ ...interval }));
    },
    reset() {
      requestCount = 0;
      mismatchCount = 0;
      requestIntervals = [];
      used.clear();
    },
    async request(url, request) {
      const intervals = requestIntervals;
      const startedAtMs = performance.now();
      requestCount += 1;
      try {
        let index = -1;
        try {
          const key = normalizeRequest(request);
          index = replay.findIndex(
            (entry, position) => !used.has(position) && entry.url === url && entry.key === key,
          );
        } catch {
          // A malformed request is a replay mismatch, even if the adapter catches it.
        }
        if (index === -1) {
          mismatchCount += 1;
          throw new Error("replay-mismatch");
        }
        used.add(index);
        const entry = replay[index];
        if (entry.delayMs !== undefined) {
          await new Promise((resolve) => setTimeout(resolve, entry.delayMs));
        }
        if (entry.error) throw new Error(entry.error);
        return Uint8Array.from(entry.response);
      } finally {
        const endedAtMs = performance.now();
        intervals.push({
          url,
          startedAtMs,
          endedAtMs,
          durationMs: endedAtMs - startedAtMs,
        });
      }
    },
  };
};

const buildContext = (fixture, policy, transport) => ({
  policy,
  clockMs: fixture.clockMs,
  transport,
  ocspRequests: fixture.transport.map(({ url, requestBase64 }) => ({
    url,
    request: Uint8Array.from(Buffer.from(requestBase64, "base64")),
  })),
});

const timedVerify = async (verifier, input, transport) => {
  const cpuBefore = cpuUsage();
  const wallBefore = performance.now();
  const result = await verifier.verify(input);
  return {
    result,
    cpuMicros: cpuMicroseconds(cpuBefore, cpuUsage()),
    wallMicros: toMicroseconds(performance.now() - wallBefore),
    requestCount: transport.requestCount,
    mismatchCount: transport.mismatchCount,
    requestIntervals: transport.requestIntervals,
  };
};

const validateSample = (fixture, sample) => {
  const failures = [];
  if (sample.mismatchCount) failures.push(`replay mismatches=${sample.mismatchCount}`);
  if (sample.result.outcome !== fixture.expectation) {
    failures.push(`outcome=${sample.result.outcome}, expected=${fixture.expectation}`);
  }
  if (fixture.expectedRequests !== undefined && sample.requestCount !== fixture.expectedRequests) {
    failures.push(`requests=${sample.requestCount}, expected=${fixture.expectedRequests}`);
  }
  if (fixture.reason !== undefined && sample.result.reason !== fixture.reason) {
    failures.push(`reason=${sample.result.reason}, expected=${fixture.reason}`);
  }
  return failures;
};

const verificationInput = ({ jws, clockMs }) => ({ jws, clockMs });

const runVerification = async ({ verifier, transport }, input) => {
  transport.reset();
  const result = await verifier.verify(input);
  return {
    result,
    requestCount: transport.requestCount,
    mismatchCount: transport.mismatchCount,
    requestIntervals: transport.requestIntervals,
  };
};

const createWarmSampler = async (fixture, adapter, policy, options) => {
  const create = async () => {
    const transport = createOcspReplay(fixture.transport);
    const verifier = await adapter.create(buildContext(fixture, policy, transport));
    return { verifier, transport };
  };
  const input = verificationInput(fixture);
  const setupFailures = [];
  const prepare = async () => {
    const instance = await create();
    if (fixture.primeWithJws) {
      const prime = await runVerification(instance, {
        jws: fixture.primeWithJws,
        clockMs: fixture.primeClockMs ?? fixture.clockMs,
      });
      setupFailures.push(
        ...validateSample(
          { expectation: "accept", expectedRequests: fixture.transport.length },
          prime,
        ).map((failure) => `priming: ${failure}`),
      );
    }
    return instance;
  };
  const hit = fixture.cacheState === "warm-hit" ? await prepare() : undefined;
  for (let index = 0; index < options.warmup; index += 1) {
    const sample = await runVerification(hit ?? (await prepare()), input);
    setupFailures.push(...validateSample(fixture, sample).map((failure) => `warmup: ${failure}`));
  }

  return async () => {
    const instances = [];
    for (let index = 0; index < options.batch; index += 1) instances.push(hit ?? (await prepare()));
    const cpuBefore = cpuUsage();
    const wallBefore = performance.now();
    const observations = [];
    for (const instance of instances) observations.push(await runVerification(instance, input));
    const wallMicros = ((performance.now() - wallBefore) * 1000) / instances.length;
    const cpuMicros = cpuMicroseconds(cpuBefore, cpuUsage()) / instances.length;
    return {
      cpuMicros,
      wallMicros,
      operations: instances.length,
      observations: observations.map(({ result, ...replay }) => ({ ...result, ...replay })),
      failures: [
        ...setupFailures,
        ...observations.flatMap((sample) => validateSample(fixture, sample)),
      ],
    };
  };
};

const runColdChild = async (fixture, adapterUrl, policy) => {
  const { value: adapter, timing: load } = await measure(() => loadAdapter(adapterUrl));
  const transport = createOcspReplay(fixture.transport);
  const context = buildContext(fixture, policy, transport);
  const { value: verifier, timing: create } = await measure(() => adapter.create(context));
  transport.reset();
  const sample = await timedVerify(
    verifier,
    { jws: fixture.jws, clockMs: fixture.clockMs },
    transport,
  );
  const { result, ...timing } = sample;
  const { requestCount, mismatchCount, requestIntervals, ...verification } = timing;
  return {
    ...verification,
    operations: 1,
    load,
    create,
    observations: [{ ...result, requestCount, mismatchCount, requestIntervals }],
    failures: validateSample(fixture, sample),
  };
};

const measure = async (operation) => {
  const cpuBefore = cpuUsage();
  const wallBefore = performance.now();
  const value = await operation();
  return {
    value,
    timing: {
      wallMicros: toMicroseconds(performance.now() - wallBefore),
      cpuMicros: cpuMicroseconds(cpuBefore, cpuUsage()),
    },
  };
};

const spawnColdChild = (fixture, adapterUrl, suite) =>
  new Promise((resolve, reject) => {
    const child = spawn(
      execPath,
      [
        "--experimental-strip-types",
        "--disable-warning=ExperimentalWarning",
        runnerPath,
        "--child",
        "--json",
        "--fixture",
        fixture.id,
        "--adapter",
        adapterUrl.href,
        ...(suite ? ["--suite", suite.href] : []),
      ],
      { cwd: cwd(), env, stdio: ["ignore", "pipe", "pipe"] },
    );
    let output = "";
    let errors = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      errors += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(errors || `cold benchmark child exited with ${code}`));
        return;
      }
      try {
        resolve(JSON.parse(output));
      } catch (error) {
        reject(
          new Error(
            `invalid cold child output: ${error instanceof Error ? error.message : "unknown error"}`,
          ),
        );
      }
    });
  });

const selectFixtures = (fixtures, options) => {
  const selected =
    options.fixtureIds.length === 0
      ? fixtures
      : fixtures.filter(({ id }) => options.fixtureIds.includes(id));
  if (
    selected.length !==
    (options.fixtureIds.length === 0 ? selected.length : options.fixtureIds.length)
  ) {
    throw new Error("One or more requested fixtures were not found");
  }
  return selected;
};

const unsupportedResult = (fixture, adapter) => ({
  fixture: fixture.id,
  skipped: true,
  reason: `adapter does not support ${fixture.kind}; capabilities=${adapter.capabilities.join(",")}`,
});

const describeRun = ({ adapter, results }) => ({
  adapter: { name: adapter.name, version: adapter.version, capabilities: adapter.capabilities },
  results,
});

const supports = ({ adapter }, fixture) =>
  adapter.capabilities.includes(fixture.kind) && (adapter.supports?.(fixture) ?? true);

const summarizeFixture = (fixture, mode, samples) => {
  const failures = [...new Set(samples.flatMap((sample) => sample.failures))];
  return {
    fixture: fixture.id,
    mode,
    cacheState:
      mode === "cold" ? "cold" : fixture.cacheState === "cold" ? "warm-miss" : fixture.cacheState,
    expected: { outcome: fixture.expectation, requests: fixture.expectedRequests },
    summary: summarizeSamples(samples),
    phases:
      mode === "cold"
        ? {
            load: summarizeSamples(samples.map(({ load }) => load)),
            create: summarizeSamples(samples.map(({ create }) => create)),
          }
        : undefined,
    samples: samples.map(({ failures: _failures, ...sample }) => sample),
    validation: { passed: failures.length === 0, failures },
  };
};

const collectSeries = async (runs, fixture, mode, policy, options) => {
  const series = [];
  for (const run of runs) {
    const sample =
      mode === "cold"
        ? () => spawnColdChild(fixture, run.url, options.suite)
        : await createWarmSampler(fixture, run.adapter, policy, options);
    series.push({ run, sample, samples: [] });
  }
  for (let index = 0; index < options.samples; index += 1) {
    const ordered = index % 2 ? [...series].reverse() : series;
    for (const entry of ordered) entry.samples.push(await entry.sample());
  }
  for (const entry of series)
    entry.run.results.push(summarizeFixture(fixture, mode, entry.samples));
};

const ratio = (baseline, candidate) => (candidate > 0 ? baseline / candidate : null);

const compareResults = (baseline, candidate) =>
  candidate.results.flatMap((candidateResult) => {
    if (!candidateResult.validation?.passed) return [];
    const baselineResult = baseline.results.find(
      ({ fixture, mode }) => fixture === candidateResult.fixture && mode === candidateResult.mode,
    );
    if (!baselineResult?.validation?.passed) return [];
    return [
      {
        fixture: candidateResult.fixture,
        mode: candidateResult.mode,
        baselineCpuMicrosMedian: baselineResult.summary.cpuMicrosMedian,
        candidateCpuMicrosMedian: candidateResult.summary.cpuMicrosMedian,
        cpuRatio: ratio(
          baselineResult.summary.cpuMicrosMedian,
          candidateResult.summary.cpuMicrosMedian,
        ),
        cpuP95Ratio: ratio(
          baselineResult.summary.cpuMicrosP95,
          candidateResult.summary.cpuMicrosP95,
        ),
        baselineWallMicrosMedian: baselineResult.summary.wallMicrosMedian,
        candidateWallMicrosMedian: candidateResult.summary.wallMicrosMedian,
        wallRatio: ratio(
          baselineResult.summary.wallMicrosMedian,
          candidateResult.summary.wallMicrosMedian,
        ),
        wallP95Ratio: ratio(
          baselineResult.summary.wallMicrosP95,
          candidateResult.summary.wallMicrosP95,
        ),
      },
    ];
  });

export const runBenchmark = async (options = defaultOptions) => {
  const { benchmarkFixtures, benchmarkPolicy } = await loadFixtures(options.suite);
  const fixtures = selectFixtures(benchmarkFixtures, options);
  const runs = [];
  for (const url of [options.adapter, options.baseline].filter(Boolean)) {
    runs.push({ url, adapter: await loadAdapter(url), results: [] });
  }
  for (const fixture of fixtures) {
    const supported = runs.filter((run) => supports(run, fixture));
    for (const run of runs.filter((run) => !supports(run, fixture))) {
      run.results.push(unsupportedResult(fixture, run.adapter));
    }
    if (options.mode !== "cold")
      await collectSeries(supported, fixture, "warm", benchmarkPolicy, options);
    if (options.mode !== "warm" && !fixture.primeWithJws) {
      await collectSeries(supported, fixture, "cold", benchmarkPolicy, options);
    }
  }
  const [candidate, baseline] = runs.map(describeRun);
  const validationFailed = runs.some(({ results }) =>
    results.some(({ validation }) => validation?.passed === false),
  );
  return {
    ...candidate,
    schemaVersion: 2,
    node: version,
    options: {
      mode: options.mode,
      samples: options.samples,
      warmup: options.warmup,
      batch: options.batch,
    },
    validationFailed,
    baseline,
    comparison: baseline ? compareResults(baseline, candidate) : undefined,
  };
};

const help = `Usage: yarn benchmark [options]

Options:
  --adapter <path>   adapter module (default: benchmark/reference-adapter.mjs)
  --baseline <path>  optional adapter to compare against and calculate ratios
  --fixture <id>     run one fixture; may be repeated
  --mode <all|warm|cold>
  --samples <n>      measured samples (default: 15)
  --warmup <n>       warm-up calls (default: 3)
  --batch <n>        operations per warm sample (default: 20)
  --suite <path>     optional local fixture catalog and policy
  --json              emit machine-readable JSON
`;

const main = async () => {
  const options = parseArgs(argv.slice(2));
  if (options.help) {
    stdout.write(help);
    return;
  }
  if (options.child) {
    const fixturesModule = await loadFixtures(options.suite);
    const fixture = selectFixtures(fixturesModule.benchmarkFixtures, options)[0];
    const result = await runColdChild(fixture, options.adapter, fixturesModule.benchmarkPolicy);
    stdout.write(JSON.stringify(result));
    return;
  }
  const result = await runBenchmark(options);
  stdout.write(`${JSON.stringify(result, null, options.json ? 0 : 2)}\n`);
  if (result.validationFailed) process.exitCode = 1;
};

if (fileURLToPath(import.meta.url) === argv[1]) {
  main().catch((error) => {
    stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
    exit(1);
  });
}
