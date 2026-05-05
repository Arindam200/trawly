import type { Finding, ScanResult, Severity } from "../types.js";

const ORDER: Severity[] = ["critical", "high", "moderate", "low", "unknown"];

export function reportMarkdown(result: ScanResult): string {
  const lines: string[] = [];
  lines.push("# trawly report");
  lines.push("");
  lines.push(`Scanned at: \`${result.scannedAt}\``);
  lines.push(`Packages scanned: **${result.packagesScanned}**`);
  lines.push(`Findings: **${result.findings.length}**`);
  if (result.ignoredFindings.length > 0) {
    lines.push(`Ignored findings: **${result.ignoredFindings.length}**`);
  }
  if (result.baseline) {
    lines.push(
      `Baseline: **${result.baseline.new} new**, **${result.baseline.existing} existing**`,
    );
  }
  lines.push("");
  lines.push(`Severity summary: ${formatSummary(result.summary)}`);

  if (result.warnings.length > 0) {
    lines.push("");
    lines.push("## Warnings");
    for (const warning of result.warnings) lines.push(`- ${warning}`);
  }

  lines.push("");
  lines.push("## Findings");
  if (result.findings.length === 0) {
    lines.push("");
    lines.push("No active findings.");
  } else {
    lines.push("");
    lines.push("| Severity | Source | Package | Version | ID | Summary |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    for (const finding of result.findings) {
      lines.push(findingRow(finding));
    }
  }

  if (result.ignoredFindings.length > 0) {
    lines.push("");
    lines.push("## Ignored Findings");
    lines.push("");
    lines.push("| Severity | Source | Package | Version | ID | Summary |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    for (const finding of result.ignoredFindings) {
      lines.push(findingRow(finding));
    }
  }

  return lines.join("\n");
}

function formatSummary(summary: Record<Severity, number>): string {
  const parts = ORDER.filter((sev) => summary[sev] > 0).map(
    (sev) => `${sev}: ${summary[sev]}`,
  );
  return parts.length === 0 ? "none" : parts.join(", ");
}

function findingRow(finding: Finding): string {
  const id = finding.url
    ? `[${escapeCell(finding.id)}](${finding.url})`
    : escapeCell(finding.id);
  return [
    finding.severity,
    finding.source,
    escapeCell(finding.packageName),
    escapeCell(finding.installedVersion),
    id,
    escapeCell(finding.summary),
  ].join(" | ").replace(/^/, "| ").replace(/$/, " |");
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}
