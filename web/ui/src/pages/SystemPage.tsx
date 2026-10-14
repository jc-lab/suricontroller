import { useState } from "react";
import { Alert, Button, Card, Code, CopyButton, Group, NumberInput, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { IconCheck, IconCopy, IconDeviceFloppy, IconInfoCircle } from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { api, apiBase } from "../api/client";
import { useIngestStats, useSystemInfo } from "../api/hooks";
import type { Settings } from "../gen/suricontroller/api/v1/api_pb";
import { CopyText, ErrorAlert, InfoGrid, LoadingBlock, PageHeader } from "../components/common";
import { formatBytes, toNumber } from "../lib/format";

const MiB = 1024 * 1024;

/** Agent WebSocket URL derived from the page location and agent_path. */
export function agentUrl(agentPath: string): string {
  const u = new URL(agentPath || "/agent/v1/connect", window.location.href);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  u.hash = "";
  u.search = "";
  return u.href;
}

function yamlQuote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function SettingsForm({ settings }: { settings?: Settings }) {
  const qc = useQueryClient();
  const ingest = useIngestStats();
  const initial = Math.round(toNumber(settings?.logIngestQueueMaxBytes) / MiB);
  const [mib, setMib] = useState<number>(initial);
  const save = useMutation({
    mutationFn: () => api.system.updateSettings({ settings: { logIngestQueueMaxBytes: BigInt(mib) * BigInt(MiB) } }),
    meta: { errorTitle: "Failed to save settings" },
    onSuccess: (r) => {
      qc.setQueryData(["settings"], r.settings);
      void qc.invalidateQueries({ queryKey: ["ingestStats"] });
      notifications.show({ color: "green", message: "Settings saved" });
    },
  });
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <Stack>
        <NumberInput
          label="Log ingest queue capacity (MiB)"
          description={`In-memory queue between agents and log storage; the oldest records are dropped when full. Currently ${formatBytes(settings?.logIngestQueueMaxBytes)}${
            ingest.data ? `, ${formatBytes(ingest.data.queueBytes)} in use` : ""
          }.`}
          min={1}
          allowDecimal={false}
          allowNegative={false}
          thousandSeparator=","
          value={mib}
          onChange={(v) => setMib(Number(v) || 0)}
          error={mib < 1 ? "Must be at least 1 MiB" : undefined}
          maw={420}
        />
        <Group>
          <Button
            type="submit"
            leftSection={<IconDeviceFloppy size={16} />}
            disabled={mib === initial || mib < 1}
            loading={save.isPending}
          >
            Save
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

export default function SystemPage() {
  const info = useSystemInfo();
  const settings = useQuery({
    queryKey: ["settings"],
    queryFn: async () => (await api.system.getSettings({})).settings,
    refetchOnWindowFocus: false,
  });
  const snippet = info.data
    ? `controller:\n  url: ${agentUrl(info.data.agentPath)}\n  host_key: ${yamlQuote(info.data.hostKey)}\n`
    : "";
  return (
    <>
      <PageHeader title="System" description="Controller information, agent connection settings and global settings" />
      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Card withBorder>
          <Title order={5} mb="sm">
            Controller
          </Title>
          {info.isPending ? (
            <LoadingBlock />
          ) : info.isError ? (
            <ErrorAlert error={info.error} onRetry={() => info.refetch()} />
          ) : (
            <InfoGrid
              labelWidth={130}
              items={[
                ["Version", <Text size="sm" ff="monospace">{info.data.version || "dev"}</Text>],
                ["Host key", <CopyText value={info.data.hostKey} />],
                ["Fingerprint", <CopyText value={info.data.hostKeyFingerprint} />],
                ["Agent endpoint", <CopyText value={agentUrl(info.data.agentPath)} />],
                ["Agent path", <Text size="sm" ff="monospace">{info.data.agentPath}</Text>],
                ["API base", <Text size="sm" ff="monospace">{apiBase}</Text>],
              ]}
            />
          )}
        </Card>
        <Card withBorder>
          <Group justify="space-between" mb="sm">
            <Title order={5}>Agent configuration</Title>
            {snippet && (
              <CopyButton value={snippet} timeout={1500}>
                {({ copied, copy }) => (
                  <Button
                    size="xs"
                    variant="light"
                    color={copied ? "teal" : undefined}
                    leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                    onClick={copy}
                  >
                    {copied ? "Copied" : "Copy"}
                  </Button>
                )}
              </CopyButton>
            )}
          </Group>
          <Text size="sm" c="dimmed" mb="xs">
            Paste this into <code>/etc/suri-agent/agent.yaml</code> on each node. The host key pins this controller;
            agents refuse controllers with a different key.
          </Text>
          {snippet ? (
            <Code block style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {snippet}
            </Code>
          ) : info.isError ? (
            <ErrorAlert error={info.error} />
          ) : (
            <LoadingBlock h={80} />
          )}
          <Alert color="blue" variant="light" icon={<IconInfoCircle size={16} />} mt="sm" p="xs">
            <Text size="xs">
              The URL is derived from the address of this page. If agents reach the controller through a different
              hostname, tunnel or reverse proxy, adjust <code>url</code> accordingly (use <code>wss://</code> behind
              TLS). Then register each node under Nodes with its public key.
            </Text>
          </Alert>
        </Card>
        <Card withBorder>
          <Title order={5} mb="sm">
            Settings
          </Title>
          {settings.isPending ? (
            <LoadingBlock />
          ) : settings.isError ? (
            <ErrorAlert error={settings.error} onRetry={() => settings.refetch()} />
          ) : (
            <SettingsForm key={String(settings.data?.logIngestQueueMaxBytes ?? 0n)} settings={settings.data} />
          )}
        </Card>
      </SimpleGrid>
    </>
  );
}
