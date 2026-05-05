import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { applyBaseline, writeBaseline } from "../src/baseline.js";
import { ConfigError, loadConfig } from "../src/config.js";
import { applyIgnores } from "../src/ignore.js";
import { reportMarkdown } from "../src/reporters/markdown.js";
import { reportSarif } from "../src/reporters/sarif.js";
import { collectRiskSignals } from "../src/risk.js";
import type { Finding, PackageInstance, ScanResult } from "../src/types.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "trawly-"));
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "GHSA-test",
    source: "osv",
    type: "vulnerability",
    severity: "high",
    ecosystem: "npm",
    packageName: "lodash",
    installedVersion: "4.17.20",
    summary: "Prototype pollution",
    fixedVersions: ["4.17.21"],
    affectedPaths: ["node_modules/lodash"],
    fingerprint: "abc",
    aliases: ["CVE-2026-0001"],
    ...overrides,
  };
}

function result(findings: Finding[]): ScanResult {
  return {
    scannedAt: "2026-05-05T00:00:00.000Z",
    packagesScanned: 1,
    findings,
    ignoredFindings: [],
    summary: { critical: 0, high: findings.length, moderate: 0, low: 0, unknown: 0 },
    errors: [],
    warnings: [],
  };
}

describe("config", () => {
  it("loads TOML config with required ignore expiry", () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "trawly.toml"),
      [
        'failOn = "moderate"',
        "risk = false",
        'allowedRegistries = ["https://registry.npmjs.org"]',
        "",
        "[[ignore]]",
        'id = "GHSA-test"',
        'package = "lodash"',
        'expires = "2026-06-30"',
        'reason = "not reachable"',
        "",
      ].join("\n"),
    );

    const loaded = loadConfig(dir);
    expect(loaded.config.failOn).toBe("moderate");
    expect(loaded.config.risk).toBe(false);
    expect(loaded.config.ignore[0]?.expires).toBe("2026-06-30");
  });

  it("rejects ignore entries without expiry", () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "trawly.toml"),
      ['[[ignore]]', 'id = "GHSA-test"', 'reason = "missing expiry"'].join("\n"),
    );
    expect(() => loadConfig(dir)).toThrow(ConfigError);
  });
});

describe("baseline", () => {
  it("marks existing and new findings by fingerprint", () => {
    const dir = tempDir();
    const baselinePath = "baseline.json";
    writeBaseline([finding({ fingerprint: "known" })], dir, baselinePath);

    const findings = [
      finding({ fingerprint: "known" }),
      finding({ id: "GHSA-new", fingerprint: "new" }),
    ];
    const baseline = applyBaseline(findings, dir, baselinePath);

    expect(baseline).toMatchObject({ existing: 1, new: 1 });
    expect(findings.map((f) => f.baseline)).toEqual(["existing", "new"]);
  });
});

describe("ignore entries", () => {
  it("matches aliases and skips expired ignores", () => {
    const active = applyIgnores(
      [finding()],
      [
        {
          id: "CVE-2026-0001",
          package: "lodash",
          expires: "2026-06-30",
          reason: "accepted",
        },
      ],
      new Date("2026-05-05T00:00:00.000Z"),
    );
    expect(active.ignored).toHaveLength(1);

    const expired = applyIgnores(
      [finding()],
      [
        {
          id: "GHSA-test",
          expires: "2026-01-01",
          reason: "old",
        },
      ],
      new Date("2026-05-05T00:00:00.000Z"),
    );
    expect(expired.active).toHaveLength(1);
    expect(expired.warnings[0]).toContain("expired");
  });
});

describe("risk signals", () => {
  it("reports install scripts, registries, and new package age", async () => {
    const pkg: PackageInstance = {
      name: "fresh",
      version: "1.0.0",
      ecosystem: "npm",
      path: "node_modules/fresh",
      direct: true,
      dev: false,
      optional: false,
      registry: "https://evil.example",
      hasInstallScript: true,
    };
    const fakeFetch = (async () =>
      new Response(
        JSON.stringify({
          time: {
            created: "2026-05-01T00:00:00.000Z",
            "1.0.0": "2026-05-04T00:00:00.000Z",
          },
        }),
        { status: 200 },
      )) as typeof fetch;

    const out = await collectRiskSignals([pkg], {
      enabled: true,
      allowedRegistries: ["https://registry.npmjs.org"],
      fetchImpl: fakeFetch,
      now: new Date("2026-05-05T00:00:00.000Z"),
    });

    expect(out.findings.map((f) => f.id).sort()).toEqual([
      "TRAWLY-INSTALL-SCRIPT",
      "TRAWLY-NEW-PACKAGE",
      "TRAWLY-NEW-VERSION",
      "TRAWLY-UNEXPECTED-REGISTRY",
    ]);
  });
});

describe("reporters and CLI output", () => {
  it("renders Markdown and SARIF reports", () => {
    const scan = result([finding()]);
    expect(reportMarkdown(scan)).toContain("| high | osv | lodash | 4.17.20 |");
    const sarif = JSON.parse(reportSarif(scan)) as {
      version: string;
      runs: Array<{ results: unknown[] }>;
    };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.results).toHaveLength(1);
  });

  it("writes CLI output to a file", () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }, null, 2),
    );

    execFileSync(
      process.execPath,
      [
        "--import",
        "tsx/esm",
        "src/cli.ts",
        "inspect",
        dir,
        "--format",
        "markdown",
        "--output",
        "out/trawly.md",
        "--no-risk",
      ],
      { cwd: process.cwd(), stdio: "pipe" },
    );

    const outPath = join(dir, "out", "trawly.md");
    expect(existsSync(outPath)).toBe(true);
    expect(readFileSync(outPath, "utf8")).toContain("# trawly report");
  });
});
