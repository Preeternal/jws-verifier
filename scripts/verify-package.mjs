import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";

const root = new URL("../", import.meta.url);
const { name: packageName, packageManager } = JSON.parse(
  readFileSync(new URL("package.json", root), "utf8"),
);
const { NODE_OPTIONS: _workspaceLoader, ...cleanEnv } = process.env;

const run = (command, args, { cwd = root, env = cleanEnv, shell = false } = {}) => {
  const result = spawnSync(command, args, {
    cwd,
    env,
    shell,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${command} failed with ${result.status ?? result.signal}\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result.stdout;
};
const runYarn = (args, options) => {
  const windows = process.platform === "win32";
  return run("yarn", windows ? args.map((arg) => `"${arg}"`) : args, {
    ...options,
    shell: windows,
  });
};

const publishOutput = runYarn(["npm", "publish", "--dry-run", "--json"]);
const publishRecords = publishOutput
  .trim()
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line));
const publishedFiles = publishRecords
  .filter((record) => typeof record.file === "string")
  .map((record) => record.file)
  .sort();

const requiredFiles = ["dist/index.js", "dist/index.d.ts", "package.json"];
for (const file of requiredFiles) {
  if (!publishedFiles.includes(file)) {
    throw new Error(`publish dry-run does not contain ${file}`);
  }
}

for (const file of publishedFiles) {
  if (!["LICENSE", "README.md", "package.json"].includes(file) && !file.startsWith("dist/")) {
    throw new Error(`Unexpected file in package: ${file}`);
  }
}

const receiptProbe = `
const transactionId = "42";
const purchaseInfo = Buffer.from('"transaction-id" = "' + transactionId + '";').toString("base64");
const receipt = Buffer.from('"purchase-info" = "' + purchaseInfo + '";').toString("base64");
if (typeof module.createVerifier !== "function" || typeof module.ReceiptUtility !== "function") {
  throw new Error("public ESM exports are incomplete");
}
const utility = new module.ReceiptUtility();
if (utility.extractTransactionIdFromTransactionReceipt(receipt) !== transactionId) {
  throw new Error("receipt facade is not synchronous or returned an unexpected value");
}
`;

const consumer = mkdtempSync(join(tmpdir(), "jws-verifier-consumer-"));
try {
  runYarn(["pack", "--out", join(consumer, "package.tgz")]);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({
      name: "package-smoke-consumer",
      private: true,
      packageManager,
      dependencies: { [packageName]: "file:./package.tgz" },
    }),
  );
  runYarn(["install"], {
    cwd: consumer,
    env: {
      ...cleanEnv,
      YARN_ENABLE_IMMUTABLE_INSTALLS: "false",
      YARN_ENABLE_SCRIPTS: "false",
      YARN_ENABLE_GLOBAL_CACHE: "false",
      YARN_ENABLE_MIRROR: "false",
      YARN_CACHE_FOLDER: join(consumer, "cache"),
      YARN_NODE_LINKER: "node-modules",
    },
  });
  const specifier = JSON.stringify(packageName);
  writeFileSync(
    join(consumer, "probe.mjs"),
    `import * as module from ${specifier};\n${receiptProbe}`,
  );
  writeFileSync(
    join(consumer, "probe.cjs"),
    `import(${specifier}).then((module) => {${receiptProbe}}).catch((error) => { console.error(error); process.exitCode = 1; });\n`,
  );
  run(process.execPath, ["probe.mjs"], { cwd: consumer });
  run(process.execPath, ["probe.cjs"], { cwd: consumer });
} finally {
  rmSync(consumer, { recursive: true, force: true });
}

process.stdout.write(
  `Package verification passed: ${publishedFiles.length} files in publish dry run, ESM and CommonJS probes passed against the installed tarball.\n`,
);
