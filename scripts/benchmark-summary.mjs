import { existsSync, readFileSync } from "node:fs";
import { arch, cpus, platform, release } from "node:os";
import process from "node:process";

const [, , input, codecInput] = process.argv;
if (!input) throw new Error("Usage: node scripts/benchmark-summary.mjs <result.json> [codec.json]");

const readReport = (path) => {
  if (!path || !existsSync(path)) return undefined;
  const raw = readFileSync(path, "utf8").trim();
  return raw ? JSON.parse(raw) : undefined;
};
const report = readReport(input);
const codec = readReport(codecInput);
const table = (results) => [
  "| Scenario | Mode | CPU median / p95 (µs) | Wall median / p95 (µs) |",
  "| --- | --- | ---: | ---: |",
  ...results.map(
    ({ fixture, mode, summary }) =>
      `| ${fixture} | ${mode} | ${summary.cpuMicrosMedian.toFixed(1)} / ${summary.cpuMicrosP95.toFixed(1)} | ${summary.wallMicrosMedian.toFixed(1)} / ${summary.wallMicrosP95.toFixed(1)} |`,
  ),
];
const lines = [
  `## Benchmarks (${report?.node ?? codec?.node ?? process.version})`,
  "",
  `${platform()} ${release()} ${arch()} · ${cpus()[0]?.model ?? "CPU model unavailable"}`,
  ...(process.env.GITHUB_SHA ? [`Commit: \`${process.env.GITHUB_SHA}\``] : []),
  "",
  `Verifier validation: ${report ? (report.validationFailed ? "FAILED" : "passed") : "report unavailable"}`,
  "",
];

if (report) {
  lines.push(
    ...table(report.results.filter(({ validation }) => validation?.passed)),
    "",
    "### Native-crypto reference comparison",
    "",
    "The reference replays OCSP requests without validating the responses and constructs X.509 objects on cache hits. Ratios describe these implementations on shared, validated scenarios.",
    "",
    "| Scenario | Mode | Reference / verifier CPU median | Reference / verifier wall median |",
    "| --- | --- | ---: | ---: |",
    ...(report.comparison ?? []).map(
      ({ fixture, mode, cpuRatio, wallRatio }) =>
        `| ${fixture} | ${mode} | ${cpuRatio == null ? "—" : `${cpuRatio.toFixed(2)}×`} | ${wallRatio == null ? "—" : `${wallRatio.toFixed(2)}×`} |`,
    ),
    "",
  );
}
if (codec) {
  lines.push(
    "### Codec operations",
    "",
    ...table(
      Object.entries(codec.result).map(([fixture, { summary }]) => ({
        fixture,
        mode: "warm",
        summary,
      })),
    ),
    "",
  );
}
process.stdout.write(`${lines.join("\n")}\n`);
