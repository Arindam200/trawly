import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { reportJson } from "../src/reporters/json.js";
import { reportMarkdown } from "../src/reporters/markdown.js";
import { reportSarif } from "../src/reporters/sarif.js";
import { scanLockfile } from "../src/scanner.js";
import { queryOsv } from "../src/sources/osv.js";
import type { Finding, PackageInstance, ScanResult } from "../src/types.js";

const describeStress = process.env.TRAWLY_STRESS === "1" ? describe : describe.skip;

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "trawly-stress-"));
}

function makePkg(index: number): PackageInstance {
  return {
    name: `pkg-${index}`,
    version: `1.0.${index}`,
    ecosystem: "npm",
    path: `node_modules/pkg-${index}`,
    direct: index < 20,
    dev: false,
    optional: false,
  };
}

function makeFinding(index: number): Finding {
  return {
    id: `GHSA-stress-${index}`,
    source: "osv",
    type: "vulnerability",
    severity: index % 2 === 0 ? "high" : "moderate",
    ecosystem: "npm",
    packageName: `pkg-${index}`,
    installedVersion: `1.0.${index}`,
    summary: `Synthetic advisory ${index}`,
    fixedVersions: [`1.0.${index + 1}`],
    affectedPaths: [`node_modules/pkg-${index}`],
    fingerprint: `fp-${index}`,
    aliases: [],
  };
}

describe("OSV reliability", () => {
  it("retries 429 rate-limit responses with retry-after", async () => {
    let calls = 0;
    const fakeFetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/v1/querybatch")) {
        calls++;
        if (calls === 1) {
          return new Response("rate limited", {
            status: 429,
            headers: { "retry-after": "0" },
          });
        }
        return new Response(
          JSON.stringify({ results: [{ vulns: [{ id: "GHSA-rate-limit" }] }] }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          id: "GHSA-rate-limit",
          summary: "Recovered after 429",
          database_specific: { severity: "HIGH" },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const findings = await queryOsv([makePkg(1)], { fetchImpl: fakeFetch });
    expect(calls).toBe(2);
    expect(findings[0]?.id).toBe("GHSA-rate-limit");
  });

  it("keeps chunking stable for large OSV batches", async () => {
    const bodySizes: number[] = [];
    const fakeFetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/v1/querybatch")) {
        const body = JSON.parse(String(init?.body)) as { queries: unknown[] };
        bodySizes.push(body.queries.length);
        return new Response(
          JSON.stringify({ results: body.queries.map(() => ({})) }),
          { status: 200 },
        );
      }
      return new Response("unexpected", { status: 500 });
    }) as unknown as typeof fetch;

    await queryOsv(Array.from({ length: 1_205 }, (_, i) => makePkg(i)), {
      fetchImpl: fakeFetch,
    });
    expect(bodySizes).toEqual([500, 500, 205]);
  });
});

describeStress("large generated graph stress", () => {
  it("scans a 10k-package npm lockfile without duplicate package loss", async () => {
    const dir = tempDir();
    const lockfile = join(dir, "package-lock.json");
    const packages: Record<string, unknown> = {
      "": { dependencies: Object.fromEntries([[ "pkg-0", "1.0.0" ]]) },
    };
    for (let i = 0; i < 10_000; i++) {
      packages[`node_modules/pkg-${i}`] = {
        version: `1.0.${i}`,
        resolved: `https://registry.npmjs.org/pkg-${i}/-/pkg-${i}-1.0.${i}.tgz`,
      };
    }
    writeFileSync(
      lockfile,
      `${JSON.stringify({ lockfileVersion: 3, packages })}\n`,
    );

    const chunkSizes: number[] = [];
    const fakeFetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/v1/querybatch")) {
        const body = JSON.parse(String(init?.body)) as { queries: unknown[] };
        chunkSizes.push(body.queries.length);
        return new Response(
          JSON.stringify({ results: body.queries.map(() => ({})) }),
          { status: 200 },
        );
      }
      return new Response("unexpected", { status: 500 });
    }) as unknown as typeof fetch;

    const started = performance.now();
    const result = await scanLockfile({
      lockfilePath: lockfile,
      risk: false,
      fetchImpl: fakeFetch,
    });
    const elapsedMs = performance.now() - started;

    expect(result.errors).toEqual([]);
    expect(result.packagesScanned).toBe(10_000);
    expect(result.findings).toHaveLength(0);
    expect(chunkSizes).toHaveLength(20);
    expect(elapsedMs).toBeLessThan(10_000);
  });

  it("renders large JSON, Markdown, and SARIF reports with valid structure", () => {
    const findings = Array.from({ length: 2_000 }, (_, i) => makeFinding(i));
    const summary = { critical: 0, high: 1_000, moderate: 1_000, low: 0, unknown: 0 };
    const result: ScanResult = {
      scannedAt: "2026-05-05T00:00:00.000Z",
      packagesScanned: 2_000,
      findings,
      ignoredFindings: [],
      summary,
      errors: [],
      warnings: [],
    };

    expect(JSON.parse(reportJson(result)).findings).toHaveLength(2_000);
    expect(reportMarkdown(result)).toContain("| high | osv | pkg-0 | 1.0.0 |");
    const sarif = JSON.parse(reportSarif(result)) as {
      version: string;
      runs: Array<{ results: unknown[]; tool: { driver: { rules: unknown[] } } }>;
    };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.results).toHaveLength(2_000);
    expect(sarif.runs[0]?.tool.driver.rules).toHaveLength(2_000);
  });
});
