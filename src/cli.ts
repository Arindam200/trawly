import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { Command, InvalidArgumentError } from "commander";
import kleur from "kleur";
import { reportAdd, runAdd } from "./commands/add.js";
import { ConfigError, loadConfig } from "./config.js";
import { envIssuesMeetThreshold, scanEnv } from "./env-scan.js";
import { initProject } from "./init.js";
import {
  buildInstallCommand,
  buildRemoveCommand,
  detectPackageManager,
  type PackageManager,
} from "./installer/pm-detect.js";
import { runPackageManager } from "./installer/runner.js";
import { reportEnvJson, reportEnvTable } from "./reporters/env-table.js";
import { reportJson } from "./reporters/json.js";
import { reportMarkdown } from "./reporters/markdown.js";
import { reportSarif } from "./reporters/sarif.js";
import { reportTable } from "./reporters/table.js";
import { resolvePolicy } from "./policy.js";
import { meetsThreshold, ScanInputError, scanProject } from "./scanner.js";
import type { FailOnLevel, PolicyPresetName } from "./types.js";
import { TRAWLY_VERSION } from "./version.js";
import { explainWhy } from "./why.js";

const FAIL_ON_VALUES: FailOnLevel[] = [
  "critical",
  "high",
  "moderate",
  "low",
  "none",
];
const FORMAT_VALUES = ["table", "json", "markdown", "sarif"] as const;
type Format = (typeof FORMAT_VALUES)[number];
const ENV_FORMAT_VALUES = ["table", "json"] as const;
type EnvFormat = (typeof ENV_FORMAT_VALUES)[number];
const POLICY_VALUES: PolicyPresetName[] = ["ci", "strict", "library", "app"];

const PM_VALUES: PackageManager[] = ["npm", "pnpm", "yarn", "bun"];

const EXIT = {
  ok: 0,
  findings: 1,
  operational: 2,
  invalidInput: 3,
} as const;

function parseFailOn(value: string): FailOnLevel {
  if (!FAIL_ON_VALUES.includes(value as FailOnLevel)) {
    throw new InvalidArgumentError(
      `must be one of: ${FAIL_ON_VALUES.join(", ")}`,
    );
  }
  return value as FailOnLevel;
}

function parseFormat(value: string): Format {
  if (!FORMAT_VALUES.includes(value as Format)) {
    throw new InvalidArgumentError(
      `must be one of: ${FORMAT_VALUES.join(", ")}`,
    );
  }
  return value as Format;
}

function parseEnvFormat(value: string): EnvFormat {
  if (!ENV_FORMAT_VALUES.includes(value as EnvFormat)) {
    throw new InvalidArgumentError(
      `must be one of: ${ENV_FORMAT_VALUES.join(", ")}`,
    );
  }
  return value as EnvFormat;
}

function parsePolicy(value: string): PolicyPresetName {
  if (!POLICY_VALUES.includes(value as PolicyPresetName)) {
    throw new InvalidArgumentError(
      `must be one of: ${POLICY_VALUES.join(", ")}`,
    );
  }
  return value as PolicyPresetName;
}

function parsePm(value: string): PackageManager {
  if (!PM_VALUES.includes(value as PackageManager)) {
    throw new InvalidArgumentError(`must be one of: ${PM_VALUES.join(", ")}`);
  }
  return value as PackageManager;
}

function collectOption(value: string, previous: string[] = []): string[] {
  previous.push(value);
  return previous;
}

const program = new Command();

program
  .name("trawly")
  .description(
    "Dependency sanity scanner. Checks installed npm packages against the OSV advisory database.",
  )
  .version(TRAWLY_VERSION)
  .enablePositionalOptions()
  .exitOverride((err) => {
    if (err.code === "commander.helpDisplayed" || err.code === "commander.help") {
      process.exit(EXIT.ok);
    }
    if (err.code === "commander.version") process.exit(EXIT.ok);
    process.exit(EXIT.invalidInput);
  });

program
  .command("scan", { isDefault: true })
  .description(
    "Scan a project and gate on findings. Exits non-zero when --fail-on is met. Use `inspect` for a log-only run.",
  )
  .argument("[path]", "Project directory to scan", ".")
  .option(
    "--lockfile <path>",
    "Explicit lockfile path. May be repeated.",
    collectOption,
  )
  .option("--sbom <path>", "Explicit SPDX/CycloneDX SBOM path. May be repeated.", collectOption)
  .option(
    "--format <format>",
    "Output format: table | json | markdown | sarif",
    parseFormat,
    "table" as Format,
  )
  .option(
    "--fail-on <level>",
    `Exit non-zero when a finding meets this severity (${FAIL_ON_VALUES.join("|")})`,
    parseFailOn,
  )
  .option("--config <path>", "Path to trawly.toml")
  .option(
    "--policy <name>",
    `Use a built-in policy preset (${POLICY_VALUES.join("|")})`,
    parsePolicy,
  )
  .option("--baseline <path>", "Only fail on findings not present in this baseline")
  .option("--write-baseline <path>", "Write the current active findings baseline")
  .option("--output <path>", "Write report output to a file")
  .option("--risk", "Enable risk signals")
  .option("--no-risk", "Disable risk signals")
  .option("--env", "Scan committed .env files for secret-like values")
  .option("--no-env", "Disable committed .env file scanning")
  .option("--prod", "Only scan production dependencies (excludes dev)")
  .option("--include-dev", "Include dev dependencies (default)")
  .option(
    "-v, --details",
    "Show one row per advisory (full table). Default groups by package.",
  )
  .option(
    "-q, --summary",
    "Show only the one-line severity summary. Mutually exclusive with --details.",
  )
  .action(async (path: string, opts: ScanCliOptions, command: Command) => {
    await runScanCommand(path, normalizeScanOptions(opts, command), {
      gate: true,
    });
  });

program
  .command("inspect")
  .description(
    "Scan a project and print findings without gating. Always exits 0 unless an operational error occurs. Use `scan` for CI gating.",
  )
  .argument("[path]", "Project directory to scan", ".")
  .option(
    "--lockfile <path>",
    "Explicit lockfile path. May be repeated.",
    collectOption,
  )
  .option("--sbom <path>", "Explicit SPDX/CycloneDX SBOM path. May be repeated.", collectOption)
  .option(
    "--format <format>",
    "Output format: table | json | markdown | sarif",
    parseFormat,
    "table" as Format,
  )
  .option("--config <path>", "Path to trawly.toml")
  .option(
    "--policy <name>",
    `Use a built-in policy preset (${POLICY_VALUES.join("|")})`,
    parsePolicy,
  )
  .option("--baseline <path>", "Mark findings already present in this baseline")
  .option("--write-baseline <path>", "Write the current active findings baseline")
  .option("--output <path>", "Write report output to a file")
  .option("--risk", "Enable risk signals")
  .option("--no-risk", "Disable risk signals")
  .option("--env", "Scan committed .env files for secret-like values")
  .option("--no-env", "Disable committed .env file scanning")
  .option("--prod", "Only scan production dependencies (excludes dev)")
  .option("--include-dev", "Include dev dependencies (default)")
  .option(
    "-v, --details",
    "Show one row per advisory (full table). Default groups by package.",
  )
  .option(
    "-q, --summary",
    "Show only the one-line severity summary. Mutually exclusive with --details.",
  )
  .action(async (path: string, opts: InspectCliOptions, command: Command) => {
    await runScanCommand(
      path,
      {
        ...normalizeScanOptions(opts, command),
        failOn: "none" as FailOnLevel,
      },
      { gate: false },
    );
  });

program
  .command("init")
  .description(
    "Create trawly.toml and write an initial baseline so CI can focus on new findings.",
  )
  .argument("[path]", "Project directory to initialize", ".")
  .option("--config <path>", "Config path to write", "trawly.toml")
  .option("--baseline <path>", "Baseline path to write", "trawly-baseline.json")
  .option(
    "--policy <name>",
    `Initial policy preset (${POLICY_VALUES.join("|")})`,
    parsePolicy,
    "ci" as PolicyPresetName,
  )
  .option("--overwrite", "Overwrite an existing config file")
  .option("--skip-baseline", "Do not scan or write a baseline")
  .action(async (path: string, opts: InitCliOptions) => {
    await runInitCommand(path, opts);
  });

program
  .command("why")
  .description(
    "Explain where a package appears in supported lockfiles.",
  )
  .argument("<package>", "Package name to explain")
  .argument("[path]", "Project directory to inspect", ".")
  .option(
    "--lockfile <path>",
    "Explicit lockfile path. May be repeated.",
    collectOption,
  )
  .action((packageName: string, path: string, opts: WhyCliOptions) => {
    runWhyCommand(packageName, path, opts);
  });

program
  .command("add")
  .description(
    "Resolve, scan, and install packages. Vulnerable packages are blocked; clean ones are forwarded to your package manager.",
  )
  .argument("<args...>", "Packages to add (e.g. next vitest@1) : PM flags after the first package are passed through")
  .option(
    "--fail-on <level>",
    `Block install when a finding meets this severity (${FAIL_ON_VALUES.join("|")})`,
    parseFailOn,
    "high" as FailOnLevel,
  )
  .option(
    "--pm <name>",
    `Force a package manager (${PM_VALUES.join("|")}). Auto-detected by default.`,
    parsePm,
  )
  .option(
    "--allow-vulnerable",
    "Install even if vulnerabilities are found (still prints findings).",
  )
  .passThroughOptions()
  .action(async (args: string[], opts: AddCliOptions) => {
    await executeAdd(args, opts);
  });

program
  .command("install")
  .alias("i")
  .description(
    "Run the project's package manager install. With package args, behaves like `add` (gates on vulnerabilities). With none, forwards directly.",
  )
  .argument("[args...]", "Optional packages to add")
  .option(
    "--fail-on <level>",
    `Block install when a finding meets this severity (${FAIL_ON_VALUES.join("|")})`,
    parseFailOn,
    "high" as FailOnLevel,
  )
  .option(
    "--pm <name>",
    `Force a package manager (${PM_VALUES.join("|")})`,
    parsePm,
  )
  .option("--allow-vulnerable", "Install even if vulnerabilities are found.")
  .passThroughOptions()
  .action(async (args: string[], opts: AddCliOptions) => {
    if (args.length === 0) {
      // Bare install: pure passthrough.
      const pm = detectPackageManager({ override: opts.pm });
      const command = buildInstallCommand(pm, []);
      process.stdout.write(
        kleur.gray(`> ${command.bin} ${command.args.join(" ")}\n`),
      );
      try {
        const code = await runPackageManager(command);
        process.exit(code);
      } catch (err) {
        printErr(`trawly: ${(err as Error).message}`);
        process.exit(EXIT.operational);
      }
    }
    await executeAdd(args, opts);
  });

program
  .command("env")
  .description(
    "Scan for env-file leaks: tracked .env files, missing .gitignore coverage, npm-publish exposure, and secrets in .env.example.",
  )
  .argument("[path]", "Project directory to scan", ".")
  .option(
    "--format <format>",
    "Output format: table | json",
    parseEnvFormat,
    "table" as EnvFormat,
  )
  .option(
    "--fail-on <level>",
    `Exit non-zero when an issue meets this severity (${FAIL_ON_VALUES.join("|")})`,
    parseFailOn,
    "high" as FailOnLevel,
  )
  .action(async (path: string, opts: EnvCliOptions) => {
    await runEnvCommand(path, opts);
  });

program
  .command("remove")
  .alias("uninstall")
  .description(
    "Remove packages by delegating to the project's package manager (no scan).",
  )
  .argument("<args...>", "Packages to remove")
  .option(
    "--pm <name>",
    `Force a package manager (${PM_VALUES.join("|")})`,
    parsePm,
  )
  .passThroughOptions()
  .action(async (args: string[], opts: { pm?: PackageManager }) => {
    const pm = detectPackageManager({ override: opts.pm });
    const { specs, flags } = splitArgs(args);
    const command = buildRemoveCommand(pm, specs, flags);
    process.stdout.write(
      kleur.gray(`> ${command.bin} ${command.args.join(" ")}\n`),
    );
    try {
      const code = await runPackageManager(command);
      process.exit(code);
    } catch (err) {
      printErr(`trawly: ${(err as Error).message}`);
      process.exit(EXIT.operational);
    }
  });

interface ScanCliOptions {
  lockfile?: string[];
  sbom?: string[];
  format: Format;
  failOn?: FailOnLevel;
  config?: string;
  policy?: PolicyPresetName;
  baseline?: string;
  writeBaseline?: string;
  output?: string;
  risk?: boolean;
  env?: boolean;
  prod?: boolean;
  includeDev?: boolean;
  details?: boolean;
  summary?: boolean;
}

type InspectCliOptions = Omit<ScanCliOptions, "failOn">;

interface InitCliOptions {
  config: string;
  baseline: string;
  policy: PolicyPresetName;
  overwrite?: boolean;
  skipBaseline?: boolean;
}

interface WhyCliOptions {
  lockfile?: string[];
}

interface AddCliOptions {
  failOn: FailOnLevel;
  pm?: PackageManager;
  allowVulnerable?: boolean;
}

interface EnvCliOptions {
  format: EnvFormat;
  failOn: FailOnLevel;
}

function normalizeScanOptions<T extends ScanCliOptions | InspectCliOptions>(
  opts: T,
  command: Command,
): T {
  return {
    ...opts,
    risk: triStateBooleanFlag(command, "risk"),
    env: triStateBooleanFlag(command, "env"),
  };
}

function triStateBooleanFlag(
  command: Command,
  name: "risk" | "env",
): boolean | undefined {
  return command.getOptionValueSource(name) === "cli"
    ? (command.getOptionValue(name) as boolean)
    : undefined;
}

async function runEnvCommand(
  path: string,
  opts: EnvCliOptions,
): Promise<void> {
  try {
    const result = await scanEnv({ cwd: path });
    if (opts.format === "json") {
      process.stdout.write(`${reportEnvJson(result)}\n`);
    } else {
      const brand = process.stdout.isTTY === true;
      process.stdout.write(`${reportEnvTable(result, { brand })}\n`);
    }
    if (result.errors.length > 0) process.exit(EXIT.operational);
    if (envIssuesMeetThreshold(result.issues, opts.failOn)) {
      if (opts.format !== "json") {
        process.stderr.write(
          `${kleur.red(
            `× Failing because at least one issue meets --fail-on=${opts.failOn}.`,
          )}\n`,
        );
      }
      process.exit(EXIT.findings);
    }
    process.exit(EXIT.ok);
  } catch (err) {
    printErr(`trawly: ${(err as Error).message}`);
    process.exit(EXIT.operational);
  }
}

async function runScanCommand(
  path: string,
  opts: ScanCliOptions,
  { gate }: { gate: boolean },
): Promise<void> {
  if (opts.prod && opts.includeDev) {
    printErr("Cannot combine --prod and --include-dev. Choose one.");
    process.exit(EXIT.invalidInput);
  }
  if (opts.details && opts.summary) {
    printErr("Cannot combine --details and --summary. Choose one.");
    process.exit(EXIT.invalidInput);
  }

  try {
    const cwd = resolve(path);
    const config = loadConfig(cwd, opts.config).config;
    const policy = resolvePolicy(opts.policy, config.policy);
    const failOn =
      opts.failOn ?? config.failOn ?? policy?.failOn ?? ("high" as FailOnLevel);
    const result = await scanProject({
      cwd,
      lockfile: opts.lockfile,
      sbom: opts.sbom,
      config: opts.config,
      policy: opts.policy,
      baseline: opts.baseline,
      writeBaseline: opts.writeBaseline,
      risk: opts.risk,
      env: opts.env,
      includeDev: opts.includeDev,
      prodOnly: opts.prod,
    });

    const output = renderReport(result, opts);
    if (opts.output) writeOutput(cwd, opts.output, output);
    else process.stdout.write(`${output}\n`);

    if (result.errors.length > 0) {
      process.exit(EXIT.operational);
    }

    if (!gate) {
      if (opts.format === "table" && !opts.output && result.findings.length > 0) {
        process.stdout.write(
          `${kleur.gray(
            "ℹ inspect mode: exiting 0 regardless of findings. Run `trawly scan` to gate CI.",
          )}\n`,
        );
      }
      process.exit(EXIT.ok);
    }

    if (meetsThreshold(result.findings, failOn)) {
      if (opts.format !== "json") {
        process.stderr.write(
          `${kleur.red(
            `× Failing because at least one finding meets --fail-on=${failOn}.`,
          )}\n${kleur.gray(
            "  Run `trawly inspect` to log without exiting non-zero, or `trawly scan --fail-on=none` to disable the gate.",
          )}\n`,
        );
      }
      process.exit(EXIT.findings);
    }
    process.exit(EXIT.ok);
  } catch (err) {
    if (err instanceof ScanInputError || err instanceof ConfigError) {
      printErr(err.message);
      process.exit(EXIT.invalidInput);
    }
    printErr(`trawly: ${(err as Error).message}`);
    process.exit(EXIT.operational);
  }
}

async function runInitCommand(
  path: string,
  opts: InitCliOptions,
): Promise<void> {
  try {
    const result = await initProject({
      cwd: path,
      config: opts.config,
      baseline: opts.baseline,
      policy: opts.policy,
      overwrite: opts.overwrite,
      writeBaseline: !opts.skipBaseline,
    });

    const lines: string[] = [];
    lines.push(
      result.configWritten
        ? kleur.green(`✓ Wrote ${result.configPath}`)
        : kleur.gray(`~ Kept existing ${result.configPath}`),
    );
    if (!opts.skipBaseline) {
      if (result.baselineWritten && result.scan?.baseline?.written) {
        lines.push(kleur.green(`✓ Wrote ${result.scan.baseline.written}`));
        lines.push(
          kleur.gray(
            `  Baseline contains ${result.scan.baseline.total} active finding(s). Future scans can fail only on new findings with --baseline=${opts.baseline}.`,
          ),
        );
      } else {
        lines.push(kleur.gray("~ Baseline was not written."));
      }
    }
    for (const warning of result.warnings) {
      lines.push(kleur.yellow(`~ ${warning}`));
    }
    process.stdout.write(`${lines.join("\n")}\n`);
    process.exit(EXIT.ok);
  } catch (err) {
    if (err instanceof ConfigError) {
      printErr(err.message);
      process.exit(EXIT.invalidInput);
    }
    printErr(`trawly: ${(err as Error).message}`);
    process.exit(EXIT.operational);
  }
}

function runWhyCommand(
  packageName: string,
  path: string,
  opts: WhyCliOptions,
): void {
  try {
    const result = explainWhy(packageName, {
      cwd: path,
      lockfile: opts.lockfile,
    });
    if (result.lockfiles.length === 0) {
      printErr(
        "No supported lockfile found. Pass --lockfile or run in a project with package-lock.json, pnpm-lock.yaml, or yarn.lock.",
      );
      process.exit(EXIT.invalidInput);
    }
    const lines: string[] = [];
    lines.push(kleur.bold(`trawly why ${packageName}`));
    if (result.matches.length === 0) {
      lines.push(kleur.yellow("No matching package found in scanned lockfiles."));
      process.stdout.write(`${lines.join("\n")}\n`);
      process.exit(EXIT.ok);
    }
    for (const match of result.matches) {
      const pkg = match.package;
      const kind = pkg.direct ? "direct" : "transitive";
      lines.push(
        `${pkg.name}@${pkg.version} (${kind}, ${pkg.manager ?? "lockfile"})`,
      );
      lines.push(`  path: ${pkg.path}`);
      lines.push(`  chain: ${match.chain.join(" > ")}`);
      if (match.note) lines.push(kleur.gray(`  note: ${match.note}`));
      if (pkg.sourceFile) {
        lines.push(
          kleur.gray(
            `  source: ${pkg.sourceFile}${pkg.line ? `:${pkg.line}` : ""}`,
          ),
        );
      }
    }
    process.stdout.write(`${lines.join("\n")}\n`);
    process.exit(EXIT.ok);
  } catch (err) {
    printErr(`trawly: ${(err as Error).message}`);
    process.exit(EXIT.operational);
  }
}

async function executeAdd(args: string[], opts: AddCliOptions): Promise<void> {
  try {
    const result = await runAdd(args, {
      failOn: opts.failOn,
      pm: opts.pm,
      allowVulnerable: opts.allowVulnerable,
    });
    process.stdout.write(reportAdd(result));

    if (result.errored.length > 0) process.exit(EXIT.operational);
    if (result.pmExitCode !== undefined && result.pmExitCode !== 0) {
      process.exit(result.pmExitCode);
    }
    if (result.blocked.length > 0) process.exit(EXIT.findings);
    process.exit(EXIT.ok);
  } catch (err) {
    printErr(`trawly: ${(err as Error).message}`);
    process.exit(EXIT.operational);
  }
}

function splitArgs(args: string[]): { specs: string[]; flags: string[] } {
  const specs: string[] = [];
  const flags: string[] = [];
  for (const a of args) {
    if (a.startsWith("-")) flags.push(a);
    else specs.push(a);
  }
  return { specs, flags };
}

function printErr(msg: string): void {
  process.stderr.write(`${kleur.red(msg)}\n`);
}

function renderReport(
  result: Awaited<ReturnType<typeof scanProject>>,
  opts: ScanCliOptions,
): string {
  switch (opts.format) {
    case "json":
      return reportJson(result);
    case "markdown":
      return reportMarkdown(result);
    case "sarif":
      return reportSarif(result);
    case "table": {
      const view = opts.summary
        ? "summary"
        : opts.details
          ? "details"
          : "grouped";
      const brand = process.stdout.isTTY === true && !opts.output;
      return reportTable(result, { view, brand });
    }
  }
}

function writeOutput(cwd: string, path: string, content: string): void {
  const absolute = resolve(cwd, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, `${content}\n`);
}

await program.parseAsync(process.argv);
