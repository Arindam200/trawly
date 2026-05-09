import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { POLICY_PRESETS } from "./policy.js";
import { scanProject, ScanInputError } from "./scanner.js";
import type { PolicyPresetName, ScanResult } from "./types.js";

export interface InitOptions {
  cwd?: string;
  config?: string;
  baseline?: string;
  policy?: PolicyPresetName;
  risk?: boolean;
  env?: boolean;
  writeBaseline?: boolean;
  overwrite?: boolean;
  fetchImpl?: typeof fetch;
}

export interface InitResult {
  configPath: string;
  configWritten: boolean;
  baselinePath?: string;
  baselineWritten: boolean;
  scan?: ScanResult;
  warnings: string[];
}

export async function initProject(
  options: InitOptions = {},
): Promise<InitResult> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const policy = options.policy ?? "ci";
  const configPath = resolve(cwd, options.config ?? "trawly.toml");
  const baselinePath = options.baseline ?? "trawly-baseline.json";
  const warnings: string[] = [];

  let configWritten = false;
  if (options.overwrite || !existsSync(configPath)) {
    writeFileSync(configPath, renderConfig(policy, baselinePath));
    configWritten = true;
  } else {
    warnings.push(`${configPath} already exists; leaving it unchanged.`);
  }

  let scan: ScanResult | undefined;
  let baselineWritten = false;
  if (options.writeBaseline !== false) {
    try {
      scan = await scanProject({
        cwd,
        config: configPath,
        policy,
        risk: options.risk,
        env: options.env,
        writeBaseline: baselinePath,
        fetchImpl: options.fetchImpl,
      });
      baselineWritten = scan.baseline?.written !== undefined;
    } catch (err) {
      if (err instanceof ScanInputError) {
        warnings.push(
          "No supported lockfile or SBOM was found, so no baseline was written.",
        );
      } else {
        throw err;
      }
    }
  }

  return {
    configPath,
    configWritten,
    baselinePath: resolve(cwd, baselinePath),
    baselineWritten,
    scan,
    warnings,
  };
}

function renderConfig(
  policy: PolicyPresetName,
  baselinePath: string,
): string {
  const preset = POLICY_PRESETS[policy];
  return [
    `policy = "${policy}"`,
    `failOn = "${preset.failOn}"`,
    `risk = ${String(preset.risk)}`,
    `env = ${String(preset.env)}`,
    'allowedRegistries = ["https://registry.npmjs.org", "https://registry.yarnpkg.com"]',
    "",
    `# Existing findings are tracked in ${baselinePath}.`,
    "# Ignore entries must expire.",
    "# [[ignore]]",
    '# id = "GHSA-example"',
    '# package = "example-package"',
    '# expires = "2026-06-30"',
    '# reason = "Not reachable in this application"',
    "",
  ].join("\n");
}
