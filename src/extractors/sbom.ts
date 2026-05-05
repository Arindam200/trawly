import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { XMLParser } from "fast-xml-parser";
import { PackageURL } from "packageurl-js";
import type { Ecosystem, PackageInstance } from "../types.js";

interface PurlPackage {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  purl: string;
}

export function parseSbom(filePath: string): PackageInstance[] {
  const absolute = resolve(filePath);
  const raw = readFileSync(absolute, "utf8");
  const trimmed = raw.trimStart();
  if (trimmed.startsWith("{")) return parseJsonSbom(absolute, raw);
  if (trimmed.startsWith("<")) return parseCycloneDxXml(absolute, raw);
  return parseSpdxTagValue(absolute, raw);
}

function parseJsonSbom(absolute: string, raw: string): PackageInstance[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (err) {
    throw new Error(
      `Failed to parse ${absolute}: ${(err as Error).message}`,
    );
  }
  if (!isRecord(parsed)) {
    throw new Error(`SBOM ${absolute} must contain a JSON object.`);
  }
  if (Array.isArray(parsed.components)) {
    return parseCycloneDxJson(absolute, raw, parsed.components);
  }
  if (Array.isArray(parsed.packages)) {
    return parseSpdxJson(absolute, raw, parsed.packages);
  }
  throw new Error(
    `Could not detect SBOM format for ${absolute}; expected CycloneDX or SPDX.`,
  );
}

function parseCycloneDxJson(
  absolute: string,
  raw: string,
  components: unknown[],
): PackageInstance[] {
  const instances: PackageInstance[] = [];
  for (const component of components) {
    if (!isRecord(component) || typeof component.purl !== "string") continue;
    const pkg = parsePurlPackage(component.purl);
    if (!pkg) continue;
    instances.push(sbomPackage(pkg, absolute, raw, component.purl));
  }
  return dedupe(instances);
}

function parseCycloneDxXml(absolute: string, raw: string): PackageInstance[] {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "",
    textNodeName: "#text",
  });
  let parsed: unknown;
  try {
    parsed = parser.parse(raw);
  } catch (err) {
    throw new Error(
      `Failed to parse ${absolute}: ${(err as Error).message}`,
    );
  }
  const bom = isRecord(parsed) ? parsed.bom : undefined;
  const components = isRecord(bom) && isRecord(bom.components)
    ? arrayify(bom.components.component)
    : [];
  const instances: PackageInstance[] = [];
  for (const component of components) {
    if (!isRecord(component) || typeof component.purl !== "string") continue;
    const pkg = parsePurlPackage(component.purl);
    if (!pkg) continue;
    instances.push(sbomPackage(pkg, absolute, raw, component.purl));
  }
  return dedupe(instances);
}

function parseSpdxJson(
  absolute: string,
  raw: string,
  packages: unknown[],
): PackageInstance[] {
  const instances: PackageInstance[] = [];
  for (const pkgRecord of packages) {
    if (!isRecord(pkgRecord)) continue;
    const externalRefs = Array.isArray(pkgRecord.externalRefs)
      ? pkgRecord.externalRefs
      : [];
    for (const ref of externalRefs) {
      if (!isRecord(ref)) continue;
      const locator = ref.referenceLocator;
      const type = String(ref.referenceType ?? "").toLowerCase();
      if (type !== "purl" || typeof locator !== "string") continue;
      const pkg = parsePurlPackage(locator);
      if (!pkg) continue;
      instances.push(sbomPackage(pkg, absolute, raw, locator));
    }
  }
  return dedupe(instances);
}

function parseSpdxTagValue(absolute: string, raw: string): PackageInstance[] {
  if (!raw.includes("SPDXVersion:")) {
    throw new Error(
      `Could not detect SBOM format for ${absolute}; expected CycloneDX or SPDX.`,
    );
  }
  const instances: PackageInstance[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const match = line.match(/^ExternalRef:\s+PACKAGE-MANAGER\s+purl\s+(\S+)/);
    if (!match?.[1]) continue;
    const pkg = parsePurlPackage(match[1]);
    if (!pkg) continue;
    instances.push(sbomPackage(pkg, absolute, raw, match[1]));
  }
  return dedupe(instances);
}

export function parsePurlPackage(purl: string): PurlPackage | null {
  let parsed: PackageURL;
  try {
    parsed = PackageURL.fromString(purl);
  } catch {
    return null;
  }
  if (!parsed.version) return null;
  const ecosystem = purlTypeToOsvEcosystem(parsed.type);
  if (!ecosystem) return null;
  return {
    name: purlName(parsed),
    version: parsed.version,
    ecosystem,
    purl,
  };
}

function sbomPackage(
  pkg: PurlPackage,
  absolute: string,
  raw: string,
  needle: string,
): PackageInstance {
  return {
    name: pkg.name,
    version: pkg.version,
    ecosystem: pkg.ecosystem,
    path: `${basename(absolute)}:${pkg.purl}`,
    direct: false,
    dev: false,
    optional: false,
    inputKind: "sbom",
    purl: pkg.purl,
    sourceFile: absolute,
    line: lineOf(raw, needle),
    manager: "sbom",
  };
}

function purlTypeToOsvEcosystem(type: string): string | null {
  switch (type.toLowerCase()) {
    case "npm":
      return "npm";
    case "pypi":
      return "PyPI";
    case "maven":
      return "Maven";
    case "gem":
      return "RubyGems";
    case "nuget":
      return "NuGet";
    case "golang":
    case "go":
      return "Go";
    case "cargo":
      return "crates.io";
    case "composer":
      return "Packagist";
    case "deb":
      return "Debian";
    case "apk":
      return "Alpine";
    default:
      return null;
  }
}

function purlName(purl: PackageURL): string {
  if (purl.type.toLowerCase() === "npm" && purl.namespace) {
    const scope = purl.namespace.startsWith("@")
      ? purl.namespace
      : `@${purl.namespace}`;
    return `${scope}/${purl.name}`;
  }
  return purl.namespace ? `${purl.namespace}/${purl.name}` : purl.name;
}

function dedupe(instances: PackageInstance[]): PackageInstance[] {
  const seen = new Set<string>();
  const out: PackageInstance[] = [];
  for (const instance of instances) {
    const key = instance.purl ?? `${instance.ecosystem}:${instance.name}@${instance.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(instance);
  }
  return out;
}

function arrayify(value: unknown): unknown[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function lineOf(raw: string, needle: string): number | undefined {
  const idx = raw.indexOf(needle);
  if (idx === -1) return undefined;
  return raw.slice(0, idx).split(/\r?\n/).length;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
