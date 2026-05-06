import { describe, expect, it } from "vitest";
import { reportTable } from "../src/reporters/table.js";
import type { Finding, ScanResult } from "../src/types.js";

function strip(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\u001B\[[0-9;]*m/g, "");
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "GHSA-xxxx-xxxx-xxxx",
    source: "osv",
    type: "vulnerability",
    severity: "high",
    packageName: "tar",
    installedVersion: "6.2.1",
    summary: "node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink",
    fixedVersions: ["7.5.7"],
    affectedPaths: [],
    ...overrides,
  };
}

function makeResult(findings: Finding[]): ScanResult {
  const summary = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  for (const f of findings) summary[f.severity] += 1;
  return {
    scannedAt: "2026-05-05T00:00:00.000Z",
    packagesScanned: 170,
    findings,
    summary,
    errors: [],
  };
}

describe("reportTable : grouped (default)", () => {
  it("collapses multiple advisories per package into one row", () => {
    const result = makeResult([
      makeFinding({ id: "GHSA-1", fixedVersions: ["7.5.7"] }),
      makeFinding({ id: "GHSA-2", fixedVersions: ["7.5.11"] }),
      makeFinding({ id: "GHSA-3", fixedVersions: ["7.5.3"] }),
      makeFinding({
        packageName: "undici",
        installedVersion: "5.29.0",
        id: "GHSA-4",
        severity: "moderate",
        fixedVersions: ["6.24.0", "7.24.0"],
      }),
    ]);

    const out = strip(reportTable(result));

    expect(out).toContain("2 affected");
    expect(out).toContain("4 findings");
    expect(out).toMatch(/tar\s+6\.2\.1\s+3 high\s+>=7\.5\.11/);
    expect(out).toMatch(/undici\s+5\.29\.0\s+1 moderate\s+>=7\.24\.0/);
    // Per-advisory IDs do not appear in grouped mode.
    expect(out).not.toContain("GHSA-1");
    // Hint to drop into details view.
    expect(out).toContain("--details");
  });

  it("sorts groups by top severity desc", () => {
    const result = makeResult([
      makeFinding({ packageName: "low-pkg", severity: "low" }),
      makeFinding({ packageName: "crit-pkg", severity: "critical" }),
      makeFinding({ packageName: "mid-pkg", severity: "moderate" }),
    ]);

    const out = strip(reportTable(result));
    const critIdx = out.indexOf("crit-pkg");
    const midIdx = out.indexOf("mid-pkg");
    const lowIdx = out.indexOf("low-pkg");
    expect(critIdx).toBeGreaterThan(0);
    expect(critIdx).toBeLessThan(midIdx);
    expect(midIdx).toBeLessThan(lowIdx);
  });

  it("renders dash when no fix version is available", () => {
    const result = makeResult([
      makeFinding({ packageName: "orphan", fixedVersions: [] }),
    ]);
    const out = strip(reportTable(result));
    expect(out).toMatch(/orphan\s+6\.2\.1\s+1 high\s+:/);
  });
});

describe("reportTable : details", () => {
  it("renders one row per advisory and hides the grouped hint", () => {
    const result = makeResult([
      makeFinding({ id: "GHSA-1" }),
      makeFinding({ id: "GHSA-2" }),
    ]);

    const out = strip(reportTable(result, { view: "details" }));

    expect(out).toContain("GHSA-1");
    expect(out).toContain("GHSA-2");
    expect(out).not.toContain("--details");
  });
});

describe("reportTable : summary", () => {
  it("prints only the header, summary line, and reminder", () => {
    const result = makeResult([
      makeFinding({ id: "GHSA-1" }),
      makeFinding({ id: "GHSA-2", severity: "moderate" }),
    ]);

    const out = strip(reportTable(result, { view: "summary" }));

    expect(out).toContain("Findings : high: 1  moderate: 1");
    expect(out).not.toContain("PACKAGE");
    expect(out).not.toContain("GHSA-1");
  });
});

describe("reportTable : clean scan", () => {
  it("shows a green checkmark and skips tables", () => {
    const out = strip(reportTable(makeResult([])));
    expect(out).toContain("No active findings.");
    expect(out).toContain("absence of findings is not proof of safety");
    expect(out).not.toContain("PACKAGE");
  });
});
