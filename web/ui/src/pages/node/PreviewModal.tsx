import { useState } from "react";
import { Alert, Badge, Button, Card, Group, Modal, Select, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { IconAlertTriangle, IconPlayerPlay } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { Repo, useCommits } from "../../api/hooks";
import type { Commit } from "../../gen/suricontroller/api/v1/api_pb";
import { CodeEditor } from "../../components/CodeEditor";
import { CommitId, ErrorAlert, InfoGrid, LoadingBlock } from "../../components/common";
import { firstLine, formatBytes, formatDateTime, formatNumber, shortCommit, tsDate } from "../../lib/format";

export function commitOptions(commits: Commit[] | undefined, emptyLabel?: string) {
  const opts = (commits ?? []).map((c) => ({
    value: c.id,
    label: `${shortCommit(c.id)} · ${firstLine(c.message).slice(0, 60)} · ${formatDateTime(tsDate(c.time))}`,
  }));
  return emptyLabel !== undefined ? [{ value: "", label: emptyLabel }, ...opts] : opts;
}

function Stat({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <Card withBorder padding="xs">
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text fw={700} size="lg" c={color}>
        {formatNumber(value)}
      </Text>
    </Card>
  );
}

function PreviewBody({ nodeId }: { nodeId: string }) {
  const rules = useCommits(Repo.RULES, 100);
  const config = useCommits(Repo.CONFIG, 100);
  const [rulesCommit, setRulesCommit] = useState("");
  const [configCommit, setConfigCommit] = useState("");
  const [req, setReq] = useState({ rulesCommit: "", configCommit: "" });
  const q = useQuery({
    queryKey: ["preview", nodeId, req.rulesCommit, req.configCommit],
    queryFn: () => api.deploy.previewNode({ nodeId, ...req }),
    retry: false,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
  const r = q.data;
  return (
    <Stack>
      <Group align="flex-end" wrap="wrap">
        <Select
          label="Rules commit"
          data={commitOptions(rules.data?.commits, "Effective (deployment policy)")}
          value={rulesCommit}
          onChange={(v) => setRulesCommit(v ?? "")}
          searchable
          style={{ flex: 1, minWidth: 240 }}
          comboboxProps={{ withinPortal: true }}
        />
        <Select
          label="Config commit"
          data={commitOptions(config.data?.commits, "Effective (deployment policy)")}
          value={configCommit}
          onChange={(v) => setConfigCommit(v ?? "")}
          searchable
          style={{ flex: 1, minWidth: 240 }}
          comboboxProps={{ withinPortal: true }}
        />
        <Button
          leftSection={<IconPlayerPlay size={14} />}
          loading={q.isFetching}
          onClick={() => {
            if (req.rulesCommit === rulesCommit && req.configCommit === configCommit) void q.refetch();
            else setReq({ rulesCommit, configCommit });
          }}
        >
          Render
        </Button>
      </Group>
      {q.isPending ? (
        <LoadingBlock label="Rendering bundle..." />
      ) : q.isError ? (
        <ErrorAlert error={q.error} title="Render failed" />
      ) : r ? (
        <>
          <InfoGrid
            labelWidth={120}
            items={[
              ["Rules commit", <CommitId id={r.rulesCommit} />],
              ["Config commit", <CommitId id={r.configCommit} />],
              [
                "Bundle",
                <Text size="sm" ff="monospace" title={r.bundleId}>
                  {r.bundleId.slice(0, 16)} ({formatBytes(r.bundleSize)})
                </Text>,
              ],
            ]}
          />
          {r.ruleStats && (
            <SimpleGrid cols={{ base: 2, sm: 3, md: 6 }} spacing="xs">
              <Stat label="Total rules" value={r.ruleStats.total} />
              <Stat label="Enabled" value={r.ruleStats.enabled} color="green" />
              <Stat label="Disabled" value={r.ruleStats.disabled} color="gray" />
              <Stat label="Drop" value={r.ruleStats.dropped} color="red" />
              <Stat label="Modified" value={r.ruleStats.modified} color="blue" />
              <Stat label="Enabled by flowbits" value={r.ruleStats.flowbitsEnabled} color="violet" />
            </SimpleGrid>
          )}
          {r.warnings.length > 0 && (
            <Alert color="yellow" icon={<IconAlertTriangle size={18} />} title={`${r.warnings.length} warning(s)`}>
              <Stack gap={2}>
                {r.warnings.map((w, i) => (
                  <Text size="sm" key={i} style={{ whiteSpace: "pre-wrap" }}>
                    {w}
                  </Text>
                ))}
              </Stack>
            </Alert>
          )}
          <div>
            <Group gap="xs" mb={4}>
              <Title order={6}>controller.yaml</Title>
              <Badge size="xs" variant="light" color="gray">
                merged suricata.yaml overlay
              </Badge>
            </Group>
            <CodeEditor value={r.controllerYaml || "# (empty overlay)\n"} language="yaml" readOnly height="360px" />
          </div>
        </>
      ) : null}
    </Stack>
  );
}

export function PreviewModal(props: { nodeId: string; opened: boolean; onClose: () => void }) {
  return (
    <Modal opened={props.opened} onClose={props.onClose} title={`Preview for ${props.nodeId}`} size="80rem">
      {props.opened && <PreviewBody nodeId={props.nodeId} />}
    </Modal>
  );
}
