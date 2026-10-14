import { Anchor, Badge, Card, Group, Progress, SimpleGrid, Stack, Table, Text, ThemeIcon, Title } from "@mantine/core";
import { IconAlertTriangle, IconPlugConnected, IconPlugConnectedX, IconRefresh } from "@tabler/icons-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { useIngestStats, useNodes, usePolicies } from "../api/hooks";
import type { DeployPolicy, Node } from "../gen/suricontroller/api/v1/api_pb";
import { CommitId, Empty, ErrorAlert, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import { DeployModeBadge, OnlineBadge, SyncBadge, nodeHasProblem, nodeSyncState } from "../components/badges";
import { formatBytes, formatNumber, toNumber } from "../lib/format";

function StatCard(props: { label: string; value: ReactNode; sub?: ReactNode; icon: ReactNode; color: string }) {
  return (
    <Card withBorder padding="md">
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <div>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            {props.label}
          </Text>
          <Text fw={700} fz={28} lh={1.2} mt={4}>
            {props.value}
          </Text>
          {props.sub && (
            <Text size="xs" c="dimmed" mt={4}>
              {props.sub}
            </Text>
          )}
        </div>
        <ThemeIcon variant="light" color={props.color} size={38} radius="md">
          {props.icon}
        </ThemeIcon>
      </Group>
    </Card>
  );
}

function PolicyCard({ title, policy }: { title: string; policy?: DeployPolicy }) {
  const behind = policy && policy.headCommit && policy.effectiveCommit !== policy.headCommit;
  return (
    <Card withBorder padding="md">
      <Group justify="space-between" mb="xs">
        <Text fw={600}>{title}</Text>
        <DeployModeBadge policy={policy} />
      </Group>
      {policy ? (
        <Stack gap={4}>
          <Group justify="space-between">
            <Text size="sm" c="dimmed">
              Effective (deployed)
            </Text>
            <CommitId id={policy.effectiveCommit} />
          </Group>
          <Group justify="space-between">
            <Text size="sm" c="dimmed">
              Repository head
            </Text>
            <CommitId id={policy.headCommit} />
          </Group>
          <Text size="xs" c={behind ? "orange" : "dimmed"} mt={4}>
            {!policy.headCommit
              ? "Repository is empty"
              : behind
                ? "Nodes are not running the latest commit"
                : "Nodes track the latest commit"}
          </Text>
        </Stack>
      ) : (
        <Text size="sm" c="dimmed">
          Loading...
        </Text>
      )}
    </Card>
  );
}

function problems(n: Node): string[] {
  const out: string[] = [];
  if (n.enabled && !n.online) out.push("offline");
  const s = nodeSyncState(n);
  if (s === "pending") out.push("out of sync");
  if (n.deploy?.desiredError) out.push("render error");
  if (nodeHasProblem(n) && !n.deploy?.desiredError) out.push("last apply failed");
  if (n.warnings.length) out.push(`${n.warnings.length} warning(s)`);
  return out;
}

export default function DashboardPage() {
  const nodes = useNodes();
  const policies = usePolicies(true);
  const ingest = useIngestStats();

  if (nodes.isPending) return <LoadingBlock />;
  if (nodes.isError) return <ErrorAlert error={nodes.error} onRetry={() => nodes.refetch()} />;

  const list = nodes.data;
  const enabled = list.filter((n) => n.enabled);
  const online = enabled.filter((n) => n.online).length;
  const offline = enabled.length - online;
  const outOfSync = enabled.filter((n) => !n.deploy?.inSync).length;
  const failed = list.filter(nodeHasProblem).length;
  const attention = list.filter((n) => n.enabled && problems(n).length > 0);

  const st = ingest.data;
  const cap = toNumber(st?.queueCapacityBytes);
  const used = toNumber(st?.queueBytes);
  const pct = cap > 0 ? Math.min(100, (used / cap) * 100) : 0;
  const agentDropped = st?.nodes.reduce((a, n) => a + toNumber(n.agentDropped), 0) ?? 0;

  return (
    <>
      <PageHeader title="Dashboard" description="Overview of nodes, deployments and log ingestion" />
      <SimpleGrid cols={{ base: 1, xs: 2, md: 4 }} mb="md">
        <StatCard
          label="Online"
          value={`${online} / ${enabled.length}`}
          sub={list.length !== enabled.length ? `${list.length - enabled.length} disabled` : "enabled nodes"}
          icon={<IconPlugConnected size={20} />}
          color="green"
        />
        <StatCard
          label="Offline"
          value={offline}
          sub="enabled nodes not connected"
          icon={<IconPlugConnectedX size={20} />}
          color={offline ? "gray" : "green"}
        />
        <StatCard
          label="Out of sync"
          value={outOfSync}
          sub="applied generation differs from desired"
          icon={<IconRefresh size={20} />}
          color={outOfSync ? "yellow" : "green"}
        />
        <StatCard
          label="Failures"
          value={failed}
          sub="failed / rolled back / render error"
          icon={<IconAlertTriangle size={20} />}
          color={failed ? "red" : "green"}
        />
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 3 }} mb="md">
        <PolicyCard title="Rules deployment" policy={policies.data?.rules} />
        <PolicyCard title="Config deployment" policy={policies.data?.config} />
        <Card withBorder padding="md">
          <Group justify="space-between" mb="xs">
            <Text fw={600}>Log ingest</Text>
            <Anchor component={Link} to="/logs?tab=ingest" size="xs">
              Details
            </Anchor>
          </Group>
          {ingest.isError ? (
            <ErrorAlert error={ingest.error} />
          ) : (
            <Stack gap={6}>
              <Group justify="space-between">
                <Text size="sm" c="dimmed">
                  Queue
                </Text>
                <Text size="sm">
                  {formatBytes(used)} / {formatBytes(cap)}
                </Text>
              </Group>
              <Progress value={pct} color={pct > 80 ? "red" : pct > 50 ? "yellow" : "blue"} />
              <Group justify="space-between">
                <Text size="sm" c="dimmed">
                  Written records
                </Text>
                <Text size="sm">{formatNumber(st?.writtenRecords)}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="sm" c="dimmed">
                  Dropped (controller queue)
                </Text>
                <Text size="sm" c={toNumber(st?.queueDroppedRecords) > 0 ? "red" : undefined}>
                  {formatNumber(st?.queueDroppedRecords)}
                </Text>
              </Group>
              <Group justify="space-between">
                <Text size="sm" c="dimmed">
                  Dropped (agents)
                </Text>
                <Text size="sm" c={agentDropped > 0 ? "red" : undefined}>
                  {formatNumber(agentDropped)}
                </Text>
              </Group>
            </Stack>
          )}
        </Card>
      </SimpleGrid>

      <Card withBorder padding="md">
        <Group justify="space-between" mb="sm">
          <Title order={4}>Needs attention</Title>
          <Anchor component={Link} to="/nodes" size="sm">
            All nodes
          </Anchor>
        </Group>
        {list.length === 0 ? (
          <Empty>
            No nodes registered yet. <Anchor component={Link} to="/nodes">Add a node</Anchor> to get started.
          </Empty>
        ) : attention.length === 0 ? (
          <Empty>All enabled nodes are online and in sync.</Empty>
        ) : (
          <Table.ScrollContainer minWidth={640}>
            <Table verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Node</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Deploy</Table.Th>
                  <Table.Th>Issues</Table.Th>
                  <Table.Th>Last seen</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {attention.map((n) => (
                  <Table.Tr key={n.id}>
                    <Table.Td>
                      <Anchor component={Link} to={`/nodes/${encodeURIComponent(n.id)}`} fw={500}>
                        {n.id}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>
                      <OnlineBadge node={n} />
                    </Table.Td>
                    <Table.Td>
                      <SyncBadge node={n} />
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {problems(n).map((p) => (
                          <Badge key={p} size="xs" variant="outline" color="gray">
                            {p}
                          </Badge>
                        ))}
                      </Group>
                      {n.deploy?.desiredError && (
                        <Text size="xs" c="red" mt={2} lineClamp={2}>
                          {n.deploy.desiredError}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <TimeAgo ts={n.lastSeenAt} />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>
    </>
  );
}
