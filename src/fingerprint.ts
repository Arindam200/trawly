import { createHash } from "node:crypto";
import type { Finding, PackageInstance } from "./types.js";

export function fingerprintFinding(input: {
  source: Finding["source"];
  id: string;
  ecosystem: string;
  packageName: string;
  installedVersion: string;
  type: Finding["type"];
}): string {
  return stableHash([
    input.source,
    input.type,
    input.id,
    input.ecosystem,
    input.packageName,
    input.installedVersion,
  ]);
}

export function packageKey(pkg: PackageInstance): string {
  return pkg.purl ?? `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

function stableHash(parts: string[]): string {
  return createHash("sha256").update(parts.join("\0")).digest("hex");
}
