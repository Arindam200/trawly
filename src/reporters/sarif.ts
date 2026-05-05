import type { Finding, ScanResult } from "../types.js";

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: { tags: string[]; precision: string; securitySeverity?: string };
}

export function reportSarif(result: ScanResult): string {
  const allFindings = [...result.findings, ...result.ignoredFindings];
  const rules = buildRules(allFindings);
  const sarif = {
    version: "2.1.0",
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "trawly",
            informationUri: "https://github.com/Arindam200/trawly",
            semanticVersion: "0.1.0",
            rules,
          },
        },
        results: allFindings.map((finding) => findingToResult(finding)),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function buildRules(findings: Finding[]): SarifRule[] {
  const map = new Map<string, SarifRule>();
  for (const finding of findings) {
    if (map.has(finding.id)) continue;
    map.set(finding.id, {
      id: finding.id,
      name: finding.id,
      shortDescription: { text: finding.summary },
      fullDescription: { text: finding.summary },
      helpUri: finding.url,
      properties: {
        tags: [finding.source, finding.type, finding.ecosystem],
        precision: finding.source === "osv" ? "high" : "medium",
        securitySeverity: securitySeverity(finding),
      },
    });
  }
  return [...map.values()];
}

function findingToResult(finding: Finding): Record<string, unknown> {
  const result: Record<string, unknown> = {
    ruleId: finding.id,
    level: sarifLevel(finding),
    message: {
      text: `${finding.packageName}@${finding.installedVersion}: ${finding.summary}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.sourceFile ?? finding.affectedPaths[0] ?? finding.packageName,
          },
          region: finding.line ? { startLine: finding.line } : undefined,
        },
      },
    ],
    partialFingerprints: {
      trawlyFingerprint: finding.fingerprint,
    },
    properties: {
      package: finding.packageName,
      version: finding.installedVersion,
      ecosystem: finding.ecosystem,
      source: finding.source,
      aliases: finding.aliases,
      baseline: finding.baseline,
    },
  };
  if (finding.ignored) {
    result.suppressions = [
      { kind: "external", justification: "Ignored by trawly configuration" },
    ];
  }
  return result;
}

function sarifLevel(finding: Finding): "error" | "warning" | "note" {
  if (finding.severity === "critical" || finding.severity === "high") {
    return "error";
  }
  if (finding.severity === "moderate" || finding.severity === "low") {
    return "warning";
  }
  return "note";
}

function securitySeverity(finding: Finding): string {
  switch (finding.severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "moderate":
      return "5.0";
    case "low":
      return "2.0";
    case "unknown":
      return "0.0";
  }
}
