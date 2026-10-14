import { Fragment, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { IconAlertTriangle, IconChevronDown, IconChevronRight, IconEye } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ApplyHistoryEntry, Node } from "../../gen/suricontroller/api/v1/api_pb";
import type { BundleRef } from "../../gen/suricontroller/agent/v1/agent_pb";
import { CommitId, Empty, ErrorAlert, InfoGrid, LoadingBlock, TimeAgo } from "../../components/common";
import { ApplyStatusBadge, SyncBadge } from "../../components/badges";
import { applyStageLabel } from "../../lib/enums";
import { formatBytes, formatDateTime, msDate, toNumber } from "../../lib/format";

function BundleInfo({ title, gen, bundle }: { title: string; gen: bigint; bundle?: BundleRef }) {
  return (
    <Card withBorder>
      <Title order={6} mb="xs">
        {title}
      </Title>
      <InfoGrid
        labelWidth={110}
        items={[
          ["Generation", <Text size="sm" ff="monospace">{String(gen)}</Text>],
          ["Rules commit", <CommitId id={bundle?.rulesCommit} />],
          ["Config commit", <CommitId id={bundle?.configCommit} />],
          [
            "Bundle",
            bundle?.bundleId ? (
              <Text size="sm" ff="monospace" title={bundle.bundleId}>
                {bundle.bundleId.slice(0, 12)} ({formatBytes(bundle.size)})
              </Text>
            ) : (
              <Text size="sm" c="dimmed">
                none
              </Text>
            ),
          ],
        ]}
      />
    </Card>
  );
}

function duration(e: ApplyHistoryEntry): string {
  const r = e.report;
  if (!r) return "-";
  const s = toNumber(r.startedAtUnixMs);
  const f = toNumber(r.finishedAtUnixMs);
  if (!s || !f || f < s) return "-";
  const ms = f - s;
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

function HistoryDetail({ entry }: { entry: ApplyHistoryEntry }) {
  const r = entry.report;
  if (!r) return null;
  return (
    <Stack gap="sm" p="sm">
      <InfoGrid
        labelWidth={130}
        items={[
          ["Started", formatDateTime(msDate(r.startedAtUnixMs))],
          ["Finished", formatDateTime(msDate(r.finishedAtUnixMs))],
          ["Stage", applyStageLabel(r.stage)],
          ["Applied rules", <CommitId id={r.applied?.bundle?.rulesCommit} />],
          ["Applied config", <CommitId id={r.applied?.bundle?.configCommit} />],
          ["Message", <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{r.message || "-"}</Text>],
        ]}
      />
      {r.warnings.length > 0 && (
        <Alert color="yellow" p="xs" title="Warnings">
          {r.warnings.map((w, i) => (
            <Text size="xs" key={i}>
              [{w.code}] {w.message}
            </Text>
          ))}
        </Alert>
      )}
      {r.ruleErrors.length > 0 && (
        <div>
          <Text size="sm" fw={600} mb={4}>
            Rule errors ({r.ruleErrors.length})
          </Text>
          <Table withTableBorder verticalSpacing={4} fz="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>SID</Table.Th>
                <Table.Th>File</Table.Th>
                <Table.Th>Line</Table.Th>
                <Table.Th>Message</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {r.ruleErrors.map((re, i) => (
                <Table.Tr key={i}>
                  <Table.Td ff="monospace">{re.sid || "-"}</Table.Td>
                  <Table.Td ff="monospace">{re.file || "-"}</Table.Td>
                  <Table.Td ff="monospace">{re.line || "-"}</Table.Td>
                  <Table.Td style={{ whiteSpace: "pre-wrap" }}>{re.message}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </div>
      )}
      {r.detail && (
        <div>
          <Text size="sm" fw={600} mb={4}>
            Detail
          </Text>
          <Code block style={{ maxHeight: 360, overflow: "auto", whiteSpace: "pre" }}>
            {r.detail}
          </Code>
        </div>
      )}
    </Stack>
  );
}

function ApplyHistory({ nodeId }: { nodeId: string }) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const q = useQuery({
    queryKey: ["applyHistory", nodeId],
    queryFn: async () => (await api.nodes.listApplyHistory({ id: nodeId, limit: 50 })).entries,
    refetchInterval: 10_000,
  });
  if (q.isPending) return <LoadingBlock />;
  if (q.isError) return <ErrorAlert error={q.error} onRetry={() => q.refetch()} />;
  if (q.data.length === 0) return <Empty>No apply reports yet.</Empty>;
  return (
    <Table.ScrollContainer minWidth={760}>
      <Table verticalSpacing="xs" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th w={32} />
            <Table.Th>Time</Table.Th>
            <Table.Th>Generation</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th>Stage</Table.Th>
            <Table.Th>Message</Table.Th>
            <Table.Th>Duration</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {q.data.map((e) => {
            const key = String(e.id);
            const r = e.report;
            const expanded = !!open[key];
            const hasMore = !!r && (r.ruleErrors.length > 0 || !!r.detail || r.warnings.length > 0);
            return (
              <Fragment key={key}>
                <Table.Tr className="clickable-row" onClick={() => setOpen((o) => ({ ...o, [key]: !o[key] }))}>
                  <Table.Td>
                    <ActionIcon variant="subtle" size="sm" color="gray">
                      {expanded ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
                    </ActionIcon>
                  </Table.Td>
                  <Table.Td>
                    <TimeAgo ts={e.createdAt} />
                  </Table.Td>
                  <Table.Td ff="monospace">{String(r?.generation ?? "-")}</Table.Td>
                  <Table.Td>{r && <ApplyStatusBadge status={r.status} />}</Table.Td>
                  <Table.Td>{r ? applyStageLabel(r.stage) : "-"}</Table.Td>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <Text size="sm" lineClamp={1} style={{ maxWidth: 420 }}>
                        {r?.message || "-"}
                      </Text>
                      {r && r.ruleErrors.length > 0 && (
                        <Badge size="xs" color="red" variant="light">
                          {r.ruleErrors.length} rule errors
                        </Badge>
                      )}
                      {hasMore && !expanded && (
                        <Text size="xs" c="dimmed">
                          details
                        </Text>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>{duration(e)}</Table.Td>
                </Table.Tr>
                {expanded && (
                  <Table.Tr>
                    <Table.Td colSpan={7} bg="var(--mantine-color-default-hover)">
                      <HistoryDetail entry={e} />
                    </Table.Td>
                  </Table.Tr>
                )}
              </Fragment>
            );
          })}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

export function DeployPanel({ node, onPreview }: { node: Node; onPreview: () => void }) {
  const d = node.deploy;
  return (
    <Stack>
      {d?.desiredError && (
        <Alert color="red" icon={<IconAlertTriangle size={18} />} title="Cannot compute the desired state">
          <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
            {d.desiredError}
          </Text>
        </Alert>
      )}
      <Card withBorder>
        <Group justify="space-between" mb="sm">
          <Group gap="sm">
            <Title order={5}>Deployment state</Title>
            <SyncBadge node={node} />
          </Group>
          <Button size="xs" variant="light" leftSection={<IconEye size={14} />} onClick={onPreview}>
            Preview bundle
          </Button>
        </Group>
        <SimpleGrid cols={{ base: 1, md: 3 }}>
          <BundleInfo title="Desired" gen={d?.desiredGeneration ?? 0n} bundle={d?.desiredBundle} />
          <BundleInfo title="Applied" gen={d?.appliedGeneration ?? 0n} bundle={d?.appliedBundle} />
          <Card withBorder>
            <Title order={6} mb="xs">
              Last report
            </Title>
            <InfoGrid
              labelWidth={80}
              items={[
                ["Status", d ? <ApplyStatusBadge status={d.lastStatus} /> : "-"],
                ["Stage", d ? applyStageLabel(d.lastStage) : "-"],
                ["When", <TimeAgo ts={d?.lastReportAt} />],
                ["Message", <Text size="sm" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{d?.lastMessage || "-"}</Text>],
              ]}
            />
          </Card>
        </SimpleGrid>
      </Card>
      <Card withBorder padding="sm">
        <Title order={5} mb="sm" px={4}>
          Apply history
        </Title>
        <ApplyHistory nodeId={node.id} />
      </Card>
    </Stack>
  );
}
