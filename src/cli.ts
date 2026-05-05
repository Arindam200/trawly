import { Command, InvalidArgumentError } from "commander";
import kleur from "kleur";
import { reportAdd, runAdd } from "./commands/add.js";
import {
  buildInstallCommand,
  buildRemoveCommand,
  detectPackageManager,
  type PackageManager,
} from "./installer/pm-detect.js";
import { runPackageManager } from "./installer/runner.js";
import { reportJson } from "./reporters/json.js";
import { reportTable } from "./reporters/table.js";
import { meetsThreshold, ScanInputError, scanProject } from "./scanner.js";
import type { FailOnLevel } from "./types.js";

const FAIL_ON_VALUES: FailOnLevel[] = [
  "critical",
  "high",
  "moderate",
  "low",
  "none",
];
const FORMAT_VALUES = ["table", "json"] as const;
type Format = (typeof FORMAT_VALUES)[number];

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

function parsePm(value: string): PackageManager {
  if (!PM_VALUES.includes(value as PackageManager)) {
    throw new InvalidArgumentError(`must be one of: ${PM_VALUES.join(", ")}`);
  }
  return value as PackageManager;
}

const TRAWLY_VERSION = "0.1.0";

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
    "Explicit path to a lockfile (package-lock.json, pnpm-lock.yaml, or yarn.lock)",
  )
  .option(
    "--format <format>",
    "Output format: table | json",
    parseFormat,
    "table" as Format,
  )
  .option(
    "--fail-on <level>",
    `Exit non-zero when a finding meets this severity (${FAIL_ON_VALUES.join("|")})`,
    parseFailOn,
    "high" as FailOnLevel,
  )
  .option("--prod", "Only scan production dependencies (excludes dev)")
  .option("--include-dev", "Include dev dependencies (default)")
  .option("--no-cache", "Bypass any local cache")
  .option(
    "-v, --details",
    "Show one row per advisory (full table). Default groups by package.",
  )
  .option(
    "-q, --summary",
    "Show only the one-line severity summary. Mutually exclusive with --details.",
  )
  .action(async (path: string, opts: ScanCliOptions) => {
    await runScanCommand(path, opts, { gate: true });
  });

program
  .command("inspect")
  .description(
    "Scan a project and print findings without gating. Always exits 0 unless an operational error occurs. Use `scan` for CI gating.",
  )
  .argument("[path]", "Project directory to scan", ".")
  .option(
    "--lockfile <path>",
    "Explicit path to a lockfile (package-lock.json, pnpm-lock.yaml, or yarn.lock)",
  )
  .option(
    "--format <format>",
    "Output format: table | json",
    parseFormat,
    "table" as Format,
  )
  .option("--prod", "Only scan production dependencies (excludes dev)")
  .option("--include-dev", "Include dev dependencies (default)")
  .option("--no-cache", "Bypass any local cache")
  .option(
    "-v, --details",
    "Show one row per advisory (full table). Default groups by package.",
  )
  .option(
    "-q, --summary",
    "Show only the one-line severity summary. Mutually exclusive with --details.",
  )
  .action(async (path: string, opts: InspectCliOptions) => {
    await runScanCommand(
      path,
      { ...opts, failOn: "none" as FailOnLevel },
      { gate: false },
    );
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
  lockfile?: string;
  format: Format;
  failOn: FailOnLevel;
  prod?: boolean;
  includeDev?: boolean;
  cache?: boolean;
  details?: boolean;
  summary?: boolean;
}

type InspectCliOptions = Omit<ScanCliOptions, "failOn">;

interface AddCliOptions {
  failOn: FailOnLevel;
  pm?: PackageManager;
  allowVulnerable?: boolean;
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
    const result = await scanProject({
      cwd: path,
      lockfile: opts.lockfile,
      includeDev: opts.includeDev,
      prodOnly: opts.prod,
      cache: opts.cache,
    });

    if (opts.format === "json") {
      process.stdout.write(`${reportJson(result)}\n`);
    } else {
      const view = opts.summary
        ? "summary"
        : opts.details
          ? "details"
          : "grouped";
      const brand = process.stdout.isTTY === true;
      process.stdout.write(`${reportTable(result, { view, brand })}\n`);
    }

    if (result.errors.length > 0) {
      process.exit(EXIT.operational);
    }

    if (!gate) {
      if (opts.format !== "json" && result.findings.length > 0) {
        process.stdout.write(
          `${kleur.gray(
            "ℹ inspect mode: exiting 0 regardless of findings. Run `trawly scan` to gate CI.",
          )}\n`,
        );
      }
      process.exit(EXIT.ok);
    }

    if (meetsThreshold(result.findings, opts.failOn)) {
      if (opts.format !== "json") {
        process.stderr.write(
          `${kleur.red(
            `× Failing because at least one finding meets --fail-on=${opts.failOn}.`,
          )}\n${kleur.gray(
            "  Run `trawly inspect` to log without exiting non-zero, or `trawly scan --fail-on=none` to disable the gate.",
          )}\n`,
        );
      }
      process.exit(EXIT.findings);
    }
    process.exit(EXIT.ok);
  } catch (err) {
    if (err instanceof ScanInputError) {
      printErr(err.message);
      process.exit(EXIT.invalidInput);
    }
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

await program.parseAsync(process.argv);
