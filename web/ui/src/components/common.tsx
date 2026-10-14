import type { ReactNode } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Center,
  CopyButton,
  Group,
  Loader,
  Stack,
  Text,
  Title,
  Tooltip,
  type MantineSize,
} from "@mantine/core";
import { IconAlertTriangle, IconCheck, IconCopy } from "@tabler/icons-react";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { errorMessage, codeName } from "../api/errors";
import { formatDateTime, relativeTime, shortCommit, tsDate } from "../lib/format";
import { useNow } from "../lib/useNow";

export function PageHeader(props: { title: ReactNode; description?: ReactNode; right?: ReactNode }) {
  return (
    <Group justify="space-between" align="flex-start" mb="md" wrap="wrap" gap="sm">
      <div style={{ minWidth: 0 }}>
        <Title order={2}>{props.title}</Title>
        {props.description && (
          <Text c="dimmed" size="sm" mt={4}>
            {props.description}
          </Text>
        )}
      </div>
      {props.right && <Group gap="xs">{props.right}</Group>}
    </Group>
  );
}

export function LoadingBlock(props: { label?: string; h?: number | string }) {
  return (
    <Center h={props.h ?? 160}>
      <Stack align="center" gap="xs">
        <Loader size="sm" />
        {props.label && (
          <Text size="sm" c="dimmed">
            {props.label}
          </Text>
        )}
      </Stack>
    </Center>
  );
}

export function ErrorAlert(props: { error: unknown; title?: string; onRetry?: () => void }) {
  const code = codeName(props.error);
  return (
    <Alert color="red" icon={<IconAlertTriangle size={18} />} title={props.title ?? "Failed to load"}>
      <Text size="sm" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
        {errorMessage(props.error)}
      </Text>
      {(code || props.onRetry) && (
        <Group gap="xs" mt={6}>
          {code && (
            <Text size="xs" c="dimmed">
              ({code})
            </Text>
          )}
          {props.onRetry && (
            <Text size="xs" c="blue" style={{ cursor: "pointer" }} onClick={props.onRetry}>
              Retry
            </Text>
          )}
        </Group>
      )}
    </Alert>
  );
}

/** Relative time with the absolute time in a tooltip. */
export function TimeAgo(props: { ts?: Timestamp; date?: Date; size?: MantineSize; c?: string }) {
  const now = useNow();
  const d = props.date ?? tsDate(props.ts);
  if (!d) {
    return (
      <Text span size={props.size ?? "sm"} c="dimmed">
        never
      </Text>
    );
  }
  return (
    <Tooltip label={formatDateTime(d)} withArrow openDelay={300}>
      <Text span size={props.size ?? "sm"} c={props.c}>
        {relativeTime(d, now)}
      </Text>
    </Tooltip>
  );
}

export function CopyIcon(props: { value: string; label?: string }) {
  return (
    <CopyButton value={props.value} timeout={1500}>
      {({ copied, copy }) => (
        <Tooltip label={copied ? "Copied" : (props.label ?? "Copy")} withArrow>
          <ActionIcon variant="subtle" color={copied ? "teal" : "gray"} size="sm" onClick={copy}>
            {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
          </ActionIcon>
        </Tooltip>
      )}
    </CopyButton>
  );
}

/** Monospace value with a copy button. */
export function CopyText(props: { value: string; display?: ReactNode; wrap?: boolean }) {
  return (
    <Group gap={4} wrap="nowrap" align="flex-start">
      <Text
        size="sm"
        ff="monospace"
        style={{ wordBreak: "break-all", whiteSpace: props.wrap === false ? "nowrap" : "normal", minWidth: 0 }}
      >
        {props.display ?? props.value}
      </Text>
      {props.value && <CopyIcon value={props.value} />}
    </Group>
  );
}

/** Short commit id with the full id in a tooltip. */
export function CommitId(props: { id?: string; size?: MantineSize }) {
  if (!props.id) {
    return (
      <Text span size={props.size ?? "sm"} c="dimmed">
        none
      </Text>
    );
  }
  return (
    <Tooltip label={props.id} withArrow openDelay={300}>
      <Text span size={props.size ?? "sm"} ff="monospace">
        {shortCommit(props.id)}
      </Text>
    </Tooltip>
  );
}

export function YesNo(props: { value: boolean; yes?: string; no?: string }) {
  return (
    <Badge variant="light" color={props.value ? "green" : "gray"} size="sm">
      {props.value ? (props.yes ?? "yes") : (props.no ?? "no")}
    </Badge>
  );
}

/** Two-column key/value list. */
export function InfoGrid(props: { items: [ReactNode, ReactNode][]; labelWidth?: number }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: `minmax(90px, ${props.labelWidth ?? 160}px) minmax(0, 1fr)`,
        columnGap: 16,
        rowGap: 8,
        alignItems: "baseline",
      }}
    >
      {props.items.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <Text size="sm" c="dimmed">
            {k}
          </Text>
          <div style={{ minWidth: 0, fontSize: "var(--mantine-font-size-sm)" }}>{v ?? "-"}</div>
        </div>
      ))}
    </div>
  );
}

export function Empty(props: { children: ReactNode }) {
  return (
    <Text c="dimmed" size="sm" ta="center" py="lg">
      {props.children}
    </Text>
  );
}
