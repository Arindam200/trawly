import { describe, expect, it, vi } from "vitest";
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
import { scanEnvFiles } from "../src/env.js";
import { fingerprintFinding } from "../src/fingerprint.js";
import { initProject } from "../src/init.js";
import { applyIgnores } from "../src/ignore.js";
import { reportMarkdown } from "../src/reporters/markdown.js";
import { reportSarif } from "../src/reporters/sarif.js";
import { collectRiskSignals } from "../src/risk.js";
import { meetsThreshold, scanLockfile, scanProject } from "../src/scanner.js";
import type { Finding, PackageInstance, ScanResult } from "../src/types.js";
import { TRAWLY_VERSION } from "../src/version.js";
import { explainWhy } from "../src/why.js";

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
  const summary = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  for (const f of findings) summary[f.severity] += 1;
  return {
    scannedAt: "2026-05-05T00:00:00.000Z",
    packagesScanned: 1,
    findings,
    ignoredFindings: [],
    summary,
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
        'policy = "strict"',
        "risk = false",
        "env = true",
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
    expect(loaded.config.policy).toBe("strict");
    expect(loaded.config.risk).toBe(false);
    expect(loaded.config.env).toBe(true);
    expect(loaded.config.ignore[0]?.expires).toBe("2026-06-30");
  });

  it("warns when ignore and legacy IgnoredVulns are both present", () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "trawly.toml"),
      [
        "[[ignore]]",
        'id = "GHSA-new"',
        'expires = "2026-06-30"',
        'reason = "new key wins"',
        "",
        "[[IgnoredVulns]]",
        'id = "GHSA-old"',
        'expires = "2026-06-30"',
        'reason = "legacy"',
        "",
      ].join("\n"),
    );
    const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const loaded = loadConfig(dir);
      expect(loaded.config.ignore[0]?.id).toBe("GHSA-new");
      expect(warning).toHaveBeenCalledWith(
        expect.stringContaining('both "ignore" and legacy "IgnoredVulns"'),
      );
    } finally {
      warning.mockRestore();
    }
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

    expect(baseline?.result).toMatchObject({ existing: 1, new: 1 });
    expect(baseline?.findings.map((f) => f.baseline)).toEqual([
      "existing",
      "new",
    ]);
    expect(findings.map((f) => f.baseline)).toEqual([undefined, undefined]);
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

  it("reports deprecated npm versions from packument metadata", async () => {
    const pkg: PackageInstance = {
      name: "old",
      version: "1.0.0",
      ecosystem: "npm",
      path: "node_modules/old",
      direct: true,
      dev: false,
      optional: false,
    };
    const fakeFetch = (async () =>
      new Response(
        JSON.stringify({
          time: {
            created: "2020-01-01T00:00:00.000Z",
            "1.0.0": "2020-01-01T00:00:00.000Z",
          },
          versions: {
            "1.0.0": { deprecated: "use old-next instead" },
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

    expect(out.findings).toMatchObject([
      {
        id: "TRAWLY-DEPRECATED-PACKAGE",
        severity: "moderate",
        summary: "old@1.0.0 is deprecated: use old-next instead",
      },
    ]);
  });

  it("fans package-age signals out to each package instance and retries 429s", async () => {
    const pkgs: PackageInstance[] = [
      {
        name: "fresh",
        version: "1.0.0",
        ecosystem: "npm",
        path: "node_modules/fresh",
        direct: true,
        dev: false,
        optional: false,
      },
      {
        name: "fresh",
        version: "1.0.0",
        ecosystem: "npm",
        path: "node_modules/dep/node_modules/fresh",
        direct: false,
        dev: false,
        optional: false,
      },
    ];
    let calls = 0;
    const fakeFetch = (async () => {
      calls++;
      if (calls === 1) {
        return new Response("rate limited", {
          status: 429,
          headers: { "retry-after": "0" },
        });
      }
      return new Response(
        JSON.stringify({
          time: {
            created: "2026-05-01T00:00:00.000Z",
            "1.0.0": "2026-05-04T00:00:00.000Z",
          },
        }),
        { status: 200 },
      );
    }) as typeof fetch;

    const out = await collectRiskSignals(pkgs, {
      enabled: true,
      allowedRegistries: ["https://registry.npmjs.org"],
      fetchImpl: fakeFetch,
      now: new Date("2026-05-05T00:00:00.000Z"),
    });

    expect(calls).toBe(2);
    expect(out.warnings).toEqual([]);
    expect(
      out.findings
        .filter((f) => f.id === "TRAWLY-NEW-VERSION")
        .map((f) => f.affectedPaths[0])
        .sort(),
    ).toEqual([
      "node_modules/dep/node_modules/fresh",
      "node_modules/fresh",
    ]);
  });
});

describe("env scanning", () => {
  it("flags committed env files and secret-like keys without exposing values", () => {
    const dir = tempDir();
    const secretValue = "super-secret-value-123";
    writeFileSync(
      join(dir, ".env"),
      [
        "PUBLIC_URL=https://example.com",
        `DATABASE_URL=${secretValue}`,
        "API_KEY=changeme",
      ].join("\n"),
    );
    writeFileSync(join(dir, ".env.example"), "DATABASE_URL=example\n");

    const out = scanEnvFiles(dir);

    expect(out.filesScanned).toBe(1);
    expect(out.findings.map((f) => f.id).sort()).toEqual([
      "TRAWLY-ENV-FILE",
      "TRAWLY-ENV-SECRET",
    ]);
    expect(out.findings.find((f) => f.id === "TRAWLY-ENV-SECRET")).toMatchObject({
      severity: "high",
      packageName: "DATABASE_URL",
      line: 2,
    });
    expect(JSON.stringify(out)).not.toContain(secretValue);
  });

  it("skips example, sample, template, and default env variants", () => {
    const dir = tempDir();
    writeFileSync(join(dir, ".env.default"), "DATABASE_URL=real\n");
    writeFileSync(join(dir, ".env.example.local"), "TOKEN=real\n");
    writeFileSync(join(dir, ".env.production.sample"), "API_KEY=real\n");
    writeFileSync(join(dir, ".env.local"), "DATABASE_URL=real\n");

    const out = scanEnvFiles(dir);

    expect(out.filesScanned).toBe(1);
    expect(out.findings.map((f) => f.installedVersion)).toEqual([
      ".env.local",
      ".env.local",
    ]);
  });

  it("can run env-only scans when explicitly enabled", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, ".env.local"), "TOKEN=live-token-value\n");

    const out = await scanProject({
      cwd: dir,
      env: true,
      risk: false,
      fetchImpl: (async () =>
        new Response(JSON.stringify({ results: [] }), {
          status: 200,
        })) as typeof fetch,
    });

    expect(out.errors).toEqual([]);
    expect(out.packagesScanned).toBe(0);
    expect(out.findings.map((f) => f.id).sort()).toEqual([
      "TRAWLY-ENV-FILE",
      "TRAWLY-ENV-SECRET",
    ]);
  });
});

describe("scanner plumbing", () => {
  it("uses policy presets as scan defaults", async () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { devDependencies: { devonly: "1.0.0" } },
          "node_modules/devonly": { version: "1.0.0", dev: true },
        },
      }),
    );
    const fakeFetch = (async (_input: URL | RequestInfo, init?: RequestInit) => {
      if (!init?.body) {
        return new Response(
          JSON.stringify({
            time: {
              created: "2026-05-01T00:00:00.000Z",
              "1.0.0": "2026-05-04T00:00:00.000Z",
            },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ results: [] }), { status: 200 });
    }) as typeof fetch;

    const out = await scanProject({
      cwd: dir,
      policy: "library",
      fetchImpl: fakeFetch,
      now: new Date("2026-05-05T00:00:00.000Z"),
    });

    expect(out.packagesScanned).toBe(0);
  });

  it("derives cwd from SBOM-only inputs and uses the supplied clock", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "trawly.toml"), "risk = false\n");
    const sbomPath = join(dir, "bom.cdx.json");
    writeFileSync(
      sbomPath,
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [
          {
            type: "library",
            name: "left-pad",
            version: "1.3.0",
            purl: "pkg:npm/left-pad@1.3.0",
          },
        ],
      }),
    );

    const urls: string[] = [];
    const fakeFetch = (async (input: URL | RequestInfo) => {
      urls.push(String(input));
      return new Response(JSON.stringify({ results: [{}] }), { status: 200 });
    }) as typeof fetch;
    const now = new Date("2026-05-05T12:00:00.000Z");

    const out = await scanLockfile({
      lockfilePath: [],
      sbom: sbomPath,
      fetchImpl: fakeFetch,
      now,
    });

    expect(out.scannedAt).toBe(now.toISOString());
    expect(out.packagesScanned).toBe(1);
    expect(urls).toEqual(["https://api.osv.dev/v1/querybatch"]);
  });

  it("returns baseline membership on findings so gates only fail on new findings", async () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { lodash: "4.17.20" } },
          "node_modules/lodash": { version: "4.17.20" },
        },
      }),
    );
    const fingerprint = fingerprintFinding({
      source: "osv",
      type: "vulnerability",
      id: "GHSA-known",
      ecosystem: "npm",
      packageName: "lodash",
      installedVersion: "4.17.20",
    });
    writeBaseline([finding({ fingerprint })], dir, "baseline.json");
    const fakeFetch = (async (input: URL | RequestInfo) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        return new Response(
          JSON.stringify({ results: [{ vulns: [{ id: "GHSA-known" }] }] }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          id: "GHSA-known",
          summary: "Known issue",
          database_specific: { severity: "HIGH" },
        }),
        { status: 200 },
      );
    }) as typeof fetch;

    const out = await scanProject({
      cwd: dir,
      baseline: "baseline.json",
      risk: false,
      fetchImpl: fakeFetch,
    });

    expect(out.findings[0]?.baseline).toBe("existing");
    expect(out.baseline).toMatchObject({ existing: 1, new: 0 });
    expect(meetsThreshold(out.findings, "high")).toBe(false);
  });

  it("deduplicates equivalent explicit input paths before scanning", async () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { lodash: "4.17.20" } },
          "node_modules/lodash": { version: "4.17.20" },
        },
      }),
    );
    const querySizes: number[] = [];
    const fakeFetch = (async (_input: URL | RequestInfo, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { queries: unknown[] };
      querySizes.push(body.queries.length);
      return new Response(JSON.stringify({ results: [{}] }), { status: 200 });
    }) as typeof fetch;

    const out = await scanLockfile({
      cwd: dir,
      lockfilePath: ["package-lock.json", "./package-lock.json"],
      risk: false,
      fetchImpl: fakeFetch,
    });

    expect(out.packagesScanned).toBe(1);
    expect(querySizes).toEqual([1]);
  });
});

describe("init and why", () => {
  it("initializes config and writes a baseline", async () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }, null, 2),
    );

    const out = await initProject({
      cwd: dir,
      policy: "strict",
      risk: false,
      env: false,
      fetchImpl: (async () =>
        new Response(JSON.stringify({ results: [] }), {
          status: 200,
        })) as typeof fetch,
    });

    expect(out.configWritten).toBe(true);
    expect(out.baselineWritten).toBe(true);
    expect(readFileSync(join(dir, "trawly.toml"), "utf8")).toContain(
      'policy = "strict"',
    );
    expect(existsSync(join(dir, "trawly-baseline.json"))).toBe(true);
  });

  it("explains npm nested package paths", () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { parent: "1.0.0" } },
          "node_modules/parent": { version: "1.0.0" },
          "node_modules/parent/node_modules/child": { version: "2.0.0" },
        },
      }),
    );

    const out = explainWhy("child", { cwd: dir });

    expect(out.matches).toHaveLength(1);
    expect(out.matches[0]?.chain).toEqual(["parent", "child"]);
  });
});

describe("reporters and CLI output", () => {
  it("renders Markdown and SARIF reports", () => {
    const scan = result([finding()]);
    expect(reportMarkdown(scan)).toContain("| high | osv | lodash | 4.17.20 |");
    const packageJson = JSON.parse(
      readFileSync(join(process.cwd(), "package.json"), "utf8"),
    ) as { version: string };
    const sarif = JSON.parse(reportSarif(scan)) as {
      version: string;
      runs: Array<{
        tool: { driver: { semanticVersion: string } };
        results: unknown[];
      }>;
    };
    expect(TRAWLY_VERSION).toBe(packageJson.version);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.tool.driver.semanticVersion).toBe(
      packageJson.version,
    );
    expect(sarif.runs[0]?.results).toHaveLength(1);
  });

  it("uses a safe SARIF artifact URI when no source path is available", () => {
    const sarif = JSON.parse(
      reportSarif(
        result([
          finding({
            packageName: "@scope/pkg",
            installedVersion: "1.0.0",
            affectedPaths: [],
          }),
        ]),
      ),
    ) as {
      runs: Array<{
        results: Array<{
          locations: Array<{
            physicalLocation: { artifactLocation: { uri: string } };
          }>;
        }>;
      }>;
    };

    expect(
      sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation
        .artifactLocation.uri,
    ).toBe("pkg:npm/%40scope%2Fpkg@1.0.0");
  });

  it("does not enable env scanning unless the CLI flag is passed", () => {
    const dir = tempDir();
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }, null, 2),
    );
    writeFileSync(join(dir, ".env"), "TOKEN=live-token-value\n");

    const out = execFileSync(
      process.execPath,
      [
        "--import",
        "tsx/esm",
        "src/cli.ts",
        "inspect",
        dir,
        "--format",
        "json",
        "--no-risk",
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );

    const parsed = JSON.parse(out) as ScanResult;
    expect(parsed.findings).toEqual([]);
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
