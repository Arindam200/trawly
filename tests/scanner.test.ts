import { describe, expect, it } from "vitest";
import {
  compareFindings,
  meetsThreshold,
  summarize,
} from "../src/scanner.js";
import type { Finding } from "../src/types.js";

function f(
  partial: Partial<Finding> & { severity: Finding["severity"]; packageName: string },
): Finding {
  return {
    id: partial.id ?? "GHSA-x",
    source: "osv",
    type: "vulnerability",
    severity: partial.severity,
    ecosystem: partial.ecosystem ?? "npm",
    packageName: partial.packageName,
    installedVersion: partial.installedVersion ?? "1.0.0",
    summary: partial.summary ?? "",
    fixedVersions: partial.fixedVersions ?? [],
    affectedPaths: partial.affectedPaths ?? [],
    fingerprint: partial.fingerprint ?? "fp",
    aliases: partial.aliases ?? [],
    url: partial.url,
  };
}

describe("compareFindings", () => {
  it("sorts critical first, then high, moderate, low, unknown", () => {
    const findings = [
      f({ severity: "low", packageName: "a" }),
      f({ severity: "critical", packageName: "z" }),
      f({ severity: "high", packageName: "m" }),
      f({ severity: "moderate", packageName: "b" }),
      f({ severity: "unknown", packageName: "c" }),
    ];
    findings.sort(compareFindings);
    expect(findings.map((x) => x.severity)).toEqual([
      "critical",
      "high",
      "moderate",
      "low",
      "unknown",
    ]);
  });

  it("breaks severity ties with package name then version then id", () => {
    const findings = [
      f({ severity: "high", packageName: "lodash", id: "B" }),
      f({ severity: "high", packageName: "axios", id: "A" }),
      f({ severity: "high", packageName: "lodash", id: "A" }),
    ];
    findings.sort(compareFindings);
    expect(findings.map((x) => `${x.packageName}/${x.id}`)).toEqual([
      "axios/A",
      "lodash/A",
      "lodash/B",
    ]);
  });
});

describe("summarize", () => {
  it("counts findings per severity bucket", () => {
    const summary = summarize([
      f({ severity: "high", packageName: "a" }),
      f({ severity: "high", packageName: "b" }),
      f({ severity: "low", packageName: "c" }),
    ]);
    expect(summary).toEqual({
      critical: 0,
      high: 2,
      moderate: 0,
      low: 1,
      unknown: 0,
    });
  });
});

describe("meetsThreshold", () => {
  const findings = [
    f({ severity: "moderate", packageName: "a" }),
    f({ severity: "low", packageName: "b" }),
  ];

  it("returns true when a finding meets or exceeds the threshold", () => {
    expect(meetsThreshold(findings, "low")).toBe(true);
    expect(meetsThreshold(findings, "moderate")).toBe(true);
  });

  it("returns false when no finding meets the threshold", () => {
    expect(meetsThreshold(findings, "high")).toBe(false);
    expect(meetsThreshold(findings, "critical")).toBe(false);
  });

  it("returns false for the 'none' threshold even with critical findings", () => {
    expect(
      meetsThreshold(
        [f({ severity: "critical", packageName: "a" })],
        "none",
      ),
    ).toBe(false);
  });

  it("returns false on an empty findings list", () => {
    expect(meetsThreshold([], "low")).toBe(false);
  });
});
