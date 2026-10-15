import {
  ApplyStage,
  ApplyStatus,
  EndpointMode,
  InterfaceMode,
  LogType,
} from "../gen/suricontroller/agent/v1/agent_pb";
import { DeployKind, DeployMode, Repo, RotateInterval } from "../gen/suricontroller/api/v1/api_pb";

export { ApplyStage, ApplyStatus, EndpointMode, InterfaceMode, LogType, DeployKind, DeployMode, Repo, RotateInterval };

export const LOG_TYPES: { type: LogType; label: string; description: string }[] = [
  { type: LogType.EVE, label: "EVE", description: "eve.json events" },
  { type: LogType.SURICATA, label: "suricata.log", description: "Engine log" },
  { type: LogType.FAST, label: "fast.log", description: "Alert one-liners" },
  { type: LogType.STATS, label: "stats.log", description: "Engine statistics" },
  { type: LogType.AGENT, label: "agent.log", description: "suri-node-agent log" },
];

export function logTypeLabel(t: LogType): string {
  return LOG_TYPES.find((x) => x.type === t)?.label ?? "unknown";
}

export const COMMON_EVE_TYPES = [
  "alert",
  "anomaly",
  "drop",
  "dns",
  "http",
  "tls",
  "flow",
  "fileinfo",
  "smtp",
  "ssh",
  "stats",
];

export function interfaceModeLabel(m: InterfaceMode): string {
  switch (m) {
    case InterfaceMode.OFF:
      return "Off";
    case InterfaceMode.IDS:
      return "IDS";
    case InterfaceMode.IPS:
      return "IPS";
    default:
      return "Off";
  }
}

export function endpointModeLabel(m: EndpointMode): string {
  switch (m) {
    case EndpointMode.DETECT:
      return "Detect";
    case EndpointMode.PREVENT:
      return "Prevent";
    default:
      return "Off";
  }
}

export function applyStatusLabel(s: ApplyStatus): string {
  switch (s) {
    case ApplyStatus.IN_PROGRESS:
      return "In progress";
    case ApplyStatus.SUCCEEDED:
      return "Succeeded";
    case ApplyStatus.FAILED:
      return "Failed";
    case ApplyStatus.ROLLED_BACK:
      return "Rolled back";
    default:
      return "None";
  }
}

export function applyStatusColor(s: ApplyStatus): string {
  switch (s) {
    case ApplyStatus.IN_PROGRESS:
      return "blue";
    case ApplyStatus.SUCCEEDED:
      return "green";
    case ApplyStatus.FAILED:
      return "red";
    case ApplyStatus.ROLLED_BACK:
      return "orange";
    default:
      return "gray";
  }
}

export function applyStageLabel(s: ApplyStage): string {
  const name = ApplyStage[s];
  if (!name || s === ApplyStage.UNSPECIFIED) return "-";
  return name.charAt(0) + name.slice(1).toLowerCase();
}

export function deployModeLabel(m: DeployMode): string {
  switch (m) {
    case DeployMode.AUTO:
      return "Auto";
    case DeployMode.PINNED:
      return "Pinned";
    case DeployMode.PAUSED:
      return "Paused";
    default:
      return "Unknown";
  }
}

export function deployModeColor(m: DeployMode): string {
  switch (m) {
    case DeployMode.AUTO:
      return "green";
    case DeployMode.PINNED:
      return "violet";
    case DeployMode.PAUSED:
      return "orange";
    default:
      return "gray";
  }
}

export function deployKindLabel(k: DeployKind): string {
  return k === DeployKind.RULES ? "Rules" : k === DeployKind.CONFIG ? "Config" : "Unknown";
}

/** Files allowed in common/ and nodes/<id>/ of the config repository. */
export const CONFIG_FILES = [
  "suricata.yaml",
  "sources.yaml",
  "disable.conf",
  "enable.conf",
  "drop.conf",
  "modify.conf",
  "threshold.config",
];

export const CONFIG_FILE_HELP: Record<string, string> = {
  "suricata.yaml": "Suricata configuration overlay (deep-merged, node over common)",
  "sources.yaml": "Rule providers / files to use (node file replaces common)",
  "disable.conf": "Rules to disable (appended: common first)",
  "enable.conf": "Rules to enable (appended: common first)",
  "drop.conf": "Rules to convert to drop (appended: common first)",
  "modify.conf": "Rule modifications (appended: common first)",
  "threshold.config": "Thresholds / suppressions (appended)",
};
