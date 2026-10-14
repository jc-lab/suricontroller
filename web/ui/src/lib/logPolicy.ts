import type { LogCollectionPolicy, LogSource } from "../gen/suricontroller/agent/v1/agent_pb";
import { LogType } from "../gen/suricontroller/agent/v1/agent_pb";
import type { Node } from "../gen/suricontroller/api/v1/api_pb";
import { COMMON_EVE_TYPES, LOG_TYPES } from "./enums";

/** Editable form of a LogCollectionPolicy. */
export interface PolicyDraft {
  enabled: boolean;
  types: LogType[];
  eveAllTypes: boolean;
  eveTypes: string[];
}

export function draftFromPolicy(p: LogCollectionPolicy | undefined): PolicyDraft {
  if (!p) return { enabled: false, types: [], eveAllTypes: true, eveTypes: [] };
  return {
    enabled: p.enabled,
    types: LOG_TYPES.map((t) => t.type).filter((t) => p.types.includes(t)),
    eveAllTypes: p.eveAllTypes,
    eveTypes: [...p.eveTypes],
  };
}

/** Init shape accepted by the API (protobuf-es MessageInitShape). */
export function policyInit(d: PolicyDraft) {
  return {
    enabled: d.enabled,
    types: [...d.types],
    eveAllTypes: d.eveAllTypes,
    eveTypes: d.eveAllTypes ? [] : [...d.eveTypes],
  };
}

export function draftEquals(a: PolicyDraft, b: PolicyDraft): boolean {
  const sameTypes = a.types.length === b.types.length && a.types.every((t) => b.types.includes(t));
  const eveA = a.eveAllTypes ? [] : [...a.eveTypes].sort();
  const eveB = b.eveAllTypes ? [] : [...b.eveTypes].sort();
  return (
    a.enabled === b.enabled &&
    sameTypes &&
    a.eveAllTypes === b.eveAllTypes &&
    eveA.length === eveB.length &&
    eveA.every((t, i) => t === eveB[i])
  );
}

export function toggleType(d: PolicyDraft, t: LogType, on: boolean): PolicyDraft {
  const types = on ? [...new Set([...d.types, t])] : d.types.filter((x) => x !== t);
  return { ...d, types: LOG_TYPES.map((x) => x.type).filter((x) => types.includes(x)) };
}

/** Eve event types reported by nodes' log sources. */
export function reportedEveTypes(sources: LogSource[]): string[] {
  const out = new Set<string>();
  for (const s of sources) if (s.type === LogType.EVE) s.eveTypes.forEach((t) => out.add(t));
  return [...out];
}

export function eveSuggestions(nodes: Node[] | Node | undefined, selected: string[] = []): string[] {
  const list = nodes === undefined ? [] : Array.isArray(nodes) ? nodes : [nodes];
  const out = new Set<string>(COMMON_EVE_TYPES);
  list.forEach((n) => reportedEveTypes(n.logSources).forEach((t) => out.add(t)));
  selected.forEach((t) => out.add(t));
  return [...out].sort();
}

export function eveSummary(d: PolicyDraft): string {
  if (!d.types.includes(LogType.EVE)) return "EVE not collected";
  if (d.eveAllTypes) return "All event types";
  if (d.eveTypes.length === 0) return "No event types";
  if (d.eveTypes.length <= 3) return d.eveTypes.join(", ");
  return `${d.eveTypes.slice(0, 3).join(", ")} +${d.eveTypes.length - 3}`;
}
