import { Anchor, Card, Group, Progress, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { Link } from "react-router";
import { useIngestStats, useNodes } from "../../api/hooks";
import { Empty, ErrorAlert, LoadingBlock } from "../../components/common";
import { OnlineBadge } from "../../components/badges";
import { formatBytes, formatNumber, toNumber } from "../../lib/format";

function Stat({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <Card withBorder padding="sm">
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {label}
      </Text>
      <Text fw={700} size="xl" c={color}>
        {value}
      </Text>
    </Card>
  );
}

export function IngestPanel() {
  const stats = useIngestStats();
  const nodes = useNodes();
  if (stats.isPending) return <LoadingBlock />;
  if (stats.isError) return <ErrorAlert error={stats.error} onRetry={() => stats.refetch()} />;
  const s = stats.data;
  const cap = toNumber(s.queueCapacityBytes);
  const pct = cap > 0 ? Math.min(100, (toNumber(s.queueBytes) / cap) * 100) : 0;
  const byNode = new Map(s.nodes.map((n) => [n.nodeId, n]));
  const ids = [...new Set([...(nodes.data ?? []).map((n) => n.id), ...s.nodes.map((n) => n.nodeId)])].sort();
  return (
    <Stack>
      <Card withBorder>
        <Group justify="space-between" mb="xs">
          <Title order={5}>Controller ingest queue</Title>
          <Anchor component={Link} to="/system" size="xs">
            Change capacity
          </Anchor>
        </Group>
        <Group justify="space-between" mb={4}>
          <Text size="sm">
            {formatBytes(s.queueBytes)} of {formatBytes(s.queueCapacityBytes)} used
          </Text>
          <Text size="sm" c="dimmed">
            {pct.toFixed(1)}%
          </Text>
        </Group>
        <Progress value={pct} size="lg" color={pct > 80 ? "red" : pct > 50 ? "yellow" : "blue"} />
        <Text size="xs" c="dimmed" mt={6}>
          When the queue is full the oldest records are dropped.
        </Text>
      </Card>
      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        <Stat label="Written records" value={formatNumber(s.writtenRecords)} />
        <Stat
          label="Dropped by controller"
          value={formatNumber(s.queueDroppedRecords)}
          color={toNumber(s.queueDroppedRecords) > 0 ? "red" : undefined}
        />
        <Stat
          label="Dropped by agents"
          value={formatNumber(s.nodes.reduce((a, n) => a + toNumber(n.agentDropped), 0))}
          color={s.nodes.some((n) => toNumber(n.agentDropped) > 0) ? "red" : undefined}
        />
      </SimpleGrid>
      <Card withBorder padding={0}>
        <Title order={5} p="sm">
          Per node
        </Title>
        {ids.length === 0 ? (
          <Empty>No nodes.</Empty>
        ) : (
          <Table.ScrollContainer minWidth={800}>
            <Table verticalSpacing="xs" striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Node</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th ta="right">Records</Table.Th>
                  <Table.Th ta="right">Bytes</Table.Th>
                  <Table.Th ta="right">Agent dropped</Table.Th>
                  <Table.Th>Agent queue</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {ids.map((id) => {
                  const st = byNode.get(id);
                  const node = nodes.data?.find((n) => n.id === id);
                  const q = node?.logQueue;
                  const qCap = toNumber(q?.capacityBytes);
                  const qPct = qCap > 0 ? (toNumber(q?.bytes) / qCap) * 100 : 0;
                  return (
                    <Table.Tr key={id}>
                      <Table.Td>
                        <Anchor component={Link} to={`/nodes/${encodeURIComponent(id)}`} size="sm" fw={600}>
                          {id}
                        </Anchor>
                      </Table.Td>
                      <Table.Td>{node ? <OnlineBadge node={node} /> : <Text size="xs" c="dimmed">deleted</Text>}</Table.Td>
                      <Table.Td ta="right">{formatNumber(st?.records)}</Table.Td>
                      <Table.Td ta="right">{formatBytes(st?.bytes)}</Table.Td>
                      <Table.Td ta="right">
                        <Text size="sm" c={toNumber(st?.agentDropped) > 0 ? "red" : undefined}>
                          {formatNumber(st?.agentDropped)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        {q ? (
                          <Group gap="xs" wrap="nowrap">
                            <Progress value={qPct} w={100} size="sm" />
                            <Text size="xs">
                              {formatBytes(q.bytes)} / {formatBytes(q.capacityBytes)}
                            </Text>
                          </Group>
                        ) : (
                          <Text size="xs" c="dimmed">
                            -
                          </Text>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>
    </Stack>
  );
}
