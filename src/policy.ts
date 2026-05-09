import type { FailOnLevel, PolicyPresetName } from "./types.js";

export interface PolicyPreset {
  failOn: FailOnLevel;
  risk: boolean;
  env: boolean;
  includeDev: boolean;
}

export const POLICY_PRESETS: Record<PolicyPresetName, PolicyPreset> = {
  ci: {
    failOn: "high",
    risk: true,
    env: false,
    includeDev: true,
  },
  strict: {
    failOn: "moderate",
    risk: true,
    env: true,
    includeDev: true,
  },
  library: {
    failOn: "moderate",
    risk: true,
    env: false,
    includeDev: false,
  },
  app: {
    failOn: "high",
    risk: true,
    env: true,
    includeDev: true,
  },
};

export function resolvePolicy(
  requested: PolicyPresetName | undefined,
  configured: PolicyPresetName | undefined,
): PolicyPreset | undefined {
  const name = requested ?? configured;
  return name ? POLICY_PRESETS[name] : undefined;
}

