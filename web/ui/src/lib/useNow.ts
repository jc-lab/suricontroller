import { useSyncExternalStore } from "react";

// A shared clock that ticks every 10 seconds, for relative timestamps.
let now = Date.now();
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | undefined;

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  if (!timer) {
    timer = setInterval(() => {
      now = Date.now();
      listeners.forEach((l) => l());
    }, 10_000);
  }
  return () => {
    listeners.delete(cb);
    if (listeners.size === 0 && timer) {
      clearInterval(timer);
      timer = undefined;
    }
  };
}

function snapshot(): number {
  // Refresh a stale value (e.g. before the first subscriber starts the timer).
  const t = Date.now();
  if (t - now >= 10_000) now = t;
  return now;
}

export function useNow(): number {
  return useSyncExternalStore(subscribe, snapshot);
}
