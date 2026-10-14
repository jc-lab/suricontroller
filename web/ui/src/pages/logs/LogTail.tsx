import { useCallback, useEffect, useRef, useState } from "react";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  NumberInput,
  Switch,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { IconPlayerPause, IconPlayerPlay, IconPlayerStop, IconSearch, IconTrash } from "@tabler/icons-react";
import { api } from "../../api/client";
import { Code, isCode } from "../../api/errors";
import { markLoggedOut } from "../../api/queryClient";
import { LogType } from "../../gen/suricontroller/agent/v1/agent_pb";
import { ErrorAlert } from "../../components/common";
import { logTypeLabel } from "../../lib/enums";
import classes from "./LogTail.module.css";

const MAX_LINES = 5000;

type Status = "idle" | "connecting" | "streaming" | "ended" | "error";

/** Live tail of a node's log type using the TailLog server stream. */
export function LogTail({ nodeId, type }: { nodeId: string; type: LogType }) {
  const [lines, setLines] = useState(200);
  const [filter, setFilter] = useState("");
  const [follow, setFollow] = useState(true);
  const [running, setRunning] = useState(false);
  const [session, setSession] = useState(0);
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<unknown>(null);
  const [view, setView] = useState<string[]>([]);
  const [paused, setPaused] = useState(false);
  const [pendingCount, setPendingCount] = useState(0);
  const [autoScroll, setAutoScroll] = useState(true);
  const [wrap, setWrap] = useState(false);

  const params = useRef({ lines, filter, follow });
  const pausedRef = useRef(false);
  const pending = useRef<string[]>([]);
  const incoming = useRef<string[]>([]);
  const frame = useRef<number | null>(null);
  const viewport = useRef<HTMLDivElement>(null);

  const flush = useCallback(() => {
    frame.current = null;
    if (!incoming.current.length) return;
    const add = incoming.current;
    incoming.current = [];
    setView((v) => {
      const next = v.concat(add);
      return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
    });
  }, []);

  const push = useCallback(
    (l: string[]) => {
      if (!l.length) return;
      if (pausedRef.current) {
        pending.current.push(...l);
        if (pending.current.length > MAX_LINES) pending.current = pending.current.slice(-MAX_LINES);
        setPendingCount(pending.current.length);
        return;
      }
      incoming.current.push(...l);
      if (frame.current === null) frame.current = requestAnimationFrame(flush);
    },
    [flush],
  );

  useEffect(() => {
    if (!running) return;
    const ac = new AbortController();
    const p = params.current;
    setStatus("connecting");
    setError(null);
    setView([]);
    pending.current = [];
    incoming.current = [];
    setPendingCount(0);
    void (async () => {
      try {
        const stream = api.logs.tailLog(
          { nodeId, type, lines: p.lines, follow: p.follow, filter: p.filter },
          { signal: ac.signal },
        );
        for await (const res of stream) {
          setStatus("streaming");
          push(res.lines);
        }
        if (!ac.signal.aborted) {
          setStatus("ended");
          setRunning(false);
        }
      } catch (e) {
        if (ac.signal.aborted) return;
        if (isCode(e, Code.Unauthenticated)) markLoggedOut();
        setError(e);
        setStatus("error");
        setRunning(false);
      }
    })();
    return () => {
      ac.abort();
      if (frame.current !== null) {
        cancelAnimationFrame(frame.current);
        frame.current = null;
      }
    };
  }, [running, session, nodeId, type, push]);

  useEffect(() => {
    if (autoScroll && viewport.current) viewport.current.scrollTop = viewport.current.scrollHeight;
  }, [view, autoScroll]);

  const start = () => {
    params.current = { lines, filter, follow };
    setPaused(false);
    pausedRef.current = false;
    setRunning(true);
    setSession((s) => s + 1);
  };
  const stop = () => {
    setRunning(false);
    setStatus((s) => (s === "streaming" || s === "connecting" ? "ended" : s));
  };
  const togglePause = () => {
    const next = !paused;
    setPaused(next);
    pausedRef.current = next;
    if (!next && pending.current.length) {
      const l = pending.current;
      pending.current = [];
      setPendingCount(0);
      push(l);
    }
  };

  const statusBadge = {
    idle: <Badge color="gray" variant="light">idle</Badge>,
    connecting: <Badge color="blue" variant="light">connecting</Badge>,
    streaming: (
      <Badge color={paused ? "yellow" : "green"} variant="dot">
        {paused ? "paused" : params.current.follow ? "live" : "loaded"}
      </Badge>
    ),
    ended: <Badge color="gray" variant="light">stopped</Badge>,
    error: <Badge color="red" variant="light">error</Badge>,
  }[status];

  return (
    <Card withBorder padding="sm">
      <Group justify="space-between" mb="sm" wrap="wrap" align="flex-end">
        <Group gap="sm" align="flex-end" wrap="wrap">
          <NumberInput
            label="Initial lines"
            value={lines}
            onChange={(v) => setLines(Math.min(5000, Math.max(1, Number(v) || 200)))}
            min={1}
            max={5000}
            w={110}
            size="xs"
          />
          <TextInput
            label="Filter (substring)"
            placeholder="e.g. ET SCAN"
            leftSection={<IconSearch size={14} />}
            value={filter}
            onChange={(e) => setFilter(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") start();
            }}
            w={220}
            size="xs"
          />
          <Switch label="Follow" checked={follow} onChange={(e) => setFollow(e.currentTarget.checked)} size="xs" mb={6} />
          {running ? (
            <Button size="xs" color="red" variant="light" leftSection={<IconPlayerStop size={14} />} onClick={stop}>
              Stop
            </Button>
          ) : (
            <Button size="xs" leftSection={<IconPlayerPlay size={14} />} onClick={start}>
              {status === "idle" ? "Start tail" : "Restart"}
            </Button>
          )}
          {running && (
            <Tooltip label="Pause rendering; new lines are buffered" withArrow>
              <Button
                size="xs"
                variant="default"
                leftSection={paused ? <IconPlayerPlay size={14} /> : <IconPlayerPause size={14} />}
                onClick={togglePause}
              >
                {paused ? `Resume${pendingCount ? ` (${pendingCount} new)` : ""}` : "Pause"}
              </Button>
            </Tooltip>
          )}
        </Group>
        <Group gap="sm">
          <Checkbox label="Auto-scroll" checked={autoScroll} onChange={(e) => setAutoScroll(e.currentTarget.checked)} size="xs" />
          <Checkbox label="Wrap" checked={wrap} onChange={(e) => setWrap(e.currentTarget.checked)} size="xs" />
          <Button size="xs" variant="subtle" color="gray" leftSection={<IconTrash size={14} />} onClick={() => setView([])}>
            Clear
          </Button>
          {statusBadge}
        </Group>
      </Group>
      {error !== null && <ErrorAlert error={error} title="Tail failed" />}
      <div ref={viewport} className={classes.viewport}>
        {view.length === 0 ? (
          <Text size="sm" c="dimmed" p="sm">
            {status === "idle"
              ? `Press "Start tail" to stream ${logTypeLabel(type)} of ${nodeId}.`
              : status === "connecting"
                ? "Connecting..."
                : "No lines."}
          </Text>
        ) : (
          <pre className={wrap ? `${classes.pre} ${classes.wrap}` : classes.pre}>
            {view.map((l, i) => (
              <div key={i}>{l}</div>
            ))}
          </pre>
        )}
      </div>
      <Text size="xs" c="dimmed" mt={4}>
        {view.length.toLocaleString()} line(s) shown{view.length >= MAX_LINES ? ` (last ${MAX_LINES})` : ""}.
      </Text>
    </Card>
  );
}
