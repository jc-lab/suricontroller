import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";

export type Num = number | bigint;

export function toNumber(n: Num | undefined | null): number {
  if (n === undefined || n === null) return 0;
  return typeof n === "bigint" ? Number(n) : n;
}

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

export function formatBytes(n: Num | undefined | null, digits = 1): string {
  let v = toNumber(n);
  if (!Number.isFinite(v)) return "-";
  let i = 0;
  while (Math.abs(v) >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const s = i === 0 ? String(Math.round(v)) : v.toFixed(v >= 100 ? 0 : digits);
  return `${s} ${UNITS[i]}`;
}

export function formatNumber(n: Num | undefined | null): string {
  return toNumber(n).toLocaleString("en-US");
}

export function tsDate(ts: Timestamp | undefined | null): Date | undefined {
  if (!ts) return undefined;
  const d = timestampDate(ts);
  return d.getTime() > 0 ? d : undefined;
}

export function msDate(ms: Num | undefined | null): Date | undefined {
  const v = toNumber(ms);
  return v > 0 ? new Date(v) : undefined;
}

export function formatDateTime(d: Date | undefined): string {
  if (!d) return "-";
  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
}

export function relativeTime(d: Date | undefined, now: number = Date.now()): string {
  if (!d) return "never";
  const diff = Math.round((now - d.getTime()) / 1000);
  const abs = Math.abs(diff);
  let s: string;
  // Small negative values come from clock skew or the 10 s UI clock.
  if (abs < 5 || (diff < 0 && abs < 60)) return "just now";
  if (abs < 60) s = `${abs}s`;
  else if (abs < 3600) s = `${Math.floor(abs / 60)}m`;
  else if (abs < 86400) s = `${Math.floor(abs / 3600)}h`;
  else if (abs < 86400 * 30) s = `${Math.floor(abs / 86400)}d`;
  else if (abs < 86400 * 365) s = `${Math.floor(abs / (86400 * 30))}mo`;
  else s = `${Math.floor(abs / (86400 * 365))}y`;
  return diff >= 0 ? `${s} ago` : `in ${s}`;
}

export function formatDuration(seconds: Num | undefined | null): string {
  let s = Math.max(0, Math.floor(toNumber(seconds)));
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function shortCommit(id: string | undefined | null): string {
  return id ? id.slice(0, 8) : "";
}

export function firstLine(s: string | undefined | null): string {
  if (!s) return "";
  const i = s.indexOf("\n");
  return (i < 0 ? s : s.slice(0, i)).trim();
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function encodeText(s: string): Uint8Array {
  return encoder.encode(s);
}

export function decodeText(b: Uint8Array | undefined): string {
  return b ? decoder.decode(b) : "";
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
