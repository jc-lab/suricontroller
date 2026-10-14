import { useState, type ReactNode } from "react";
import {
  Anchor,
  Badge,
  Button,
  Card,
  Group,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconCheck } from "@tabler/icons-react";
import { modals } from "@mantine/modals";
import { Link } from "react-router";
import { Repo, useCommits, useNodes, usePolicies } from "../api/hooks";
import { DeployKind, DeployMode } from "../gen/suricontroller/api/v1/api_pb";
import type { Commit, DeployPolicy, Node } from "../gen/suricontroller/api/v1/api_pb";
import { CommitId, Empty, ErrorAlert, InfoGrid, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import { ApplyStatusBadge, DeployModeBadge, OnlineBadge, SyncBadge } from "../components/badges";
import { useSetPolicy } from "../components/deployActions";
import { deployKindLabel, deployModeLabel } from "../lib/enums";
import { firstLine, shortCommit } from "../lib/format";
import { commitOptions } from "./node/PreviewModal";

const MODE_HELP: Record<number, string> = {
  [DeployMode.AUTO]: "Track the repository head: every new commit is deployed to all nodes.",
  [DeployMode.PINNED]: "Deploy a fixed commit (rollback or freeze on a known version).",
  [DeployMode.PAUSED]: "Keep the current effective commit; new commits are not deployed.",
};

function commitLabel(commits: Commit[] | undefined, id: string) {
  const c = commits?.find((x) => x.id === id);
  return c ? firstLine(c.message) : "";
}

function PolicyEditor({ kind, policy }: { kind: DeployKind; policy: DeployPolicy }) {
  const repo = kind === DeployKind.RULES ? Repo.RULES : Repo.CONFIG;
  const commits = useCommits(repo, 100);
  const setPolicy = useSetPolicy();
  const [mode, setMode] = useState<DeployMode>(policy.mode);
  const [pinned, setPinned] = useState<string>(policy.pinnedCommit || policy.effectiveCommit || "");
  const label = deployKindLabel(kind);
  const changed = mode !== policy.mode || (mode === DeployMode.PINNED && pinned !== policy.pinnedCommit);
  const behind = !!policy.headCommit && policy.effectiveCommit !== policy.headCommit;

  const apply = () =>
    modals.openConfirmModal({
      title: `Change ${label.toLowerCase()} deployment`,
      children: (
        <Text size="sm">
          {mode === DeployMode.AUTO && `Nodes will track the latest ${label.toLowerCase()} commit (${shortCommit(policy.headCommit) || "none"}).`}
          {mode === DeployMode.PINNED && `All nodes will be deployed with commit ${shortCommit(pinned)}.`}
          {mode === DeployMode.PAUSED && `Deployment is frozen at ${shortCommit(policy.effectiveCommit) || "the current state"}.`}
        </Text>
      ),
      labels: { confirm: "Apply", cancel: "Cancel" },
      onConfirm: () =>
        setPolicy.mutate({ kind, mode, pinnedCommit: mode === DeployMode.PINNED ? pinned : "" }),
    });

  return (
    <Card withBorder>
      <Group justify="space-between" mb="sm">
        <Group gap="xs">
          <Title order={4}>{label}</Title>
          <DeployModeBadge policy={policy} />
        </Group>
        <Anchor component={Link} to={kind === DeployKind.RULES ? "/rules?tab=history" : "/config?tab=history"} size="xs">
          Commit history
        </Anchor>
      </Group>
      <InfoGrid
        labelWidth={130}
        items={[
          [
            "Effective commit",
            <Group gap={6}>
              <CommitId id={policy.effectiveCommit} />
              <Text size="xs" c="dimmed" lineClamp={1}>
                {commitLabel(commits.data?.commits, policy.effectiveCommit)}
              </Text>
            </Group>,
          ],
          [
            "Repository head",
            <Group gap={6}>
              <CommitId id={policy.headCommit} />
              {behind ? (
                <Badge size="xs" color="orange" variant="light">
                  not deployed
                </Badge>
              ) : policy.headCommit ? (
                <Badge size="xs" color="green" variant="light" leftSection={<IconCheck size={10} />}>
                  deployed
                </Badge>
              ) : null}
            </Group>,
          ],
          ...(policy.mode === DeployMode.PINNED
            ? ([["Pinned commit", <CommitId id={policy.pinnedCommit} />]] as [string, ReactNode][])
            : []),
          [
            "Updated",
            policy.updatedAt ? (
              <Text size="sm" span>
                <TimeAgo ts={policy.updatedAt} /> by {policy.updatedBy || "system"}
              </Text>
            ) : (
              "never (default)"
            ),
          ],
        ]}
      />
      <Stack gap="xs" mt="md">
        <SegmentedControl
          fullWidth
          value={String(mode)}
          onChange={(v) => setMode(Number(v) as DeployMode)}
          data={[DeployMode.AUTO, DeployMode.PINNED, DeployMode.PAUSED].map((m) => ({
            value: String(m),
            label: deployModeLabel(m),
          }))}
        />
        <Text size="xs" c="dimmed">
          {MODE_HELP[mode]}
        </Text>
        {mode === DeployMode.PINNED && (
          <Select
            label="Commit to deploy"
            placeholder={commits.isPending ? "Loading commits..." : "Select a commit"}
            data={commitOptions(commits.data?.commits)}
            value={pinned || null}
            onChange={(v) => setPinned(v ?? "")}
            searchable
            nothingFoundMessage="No commits"
            error={commits.isError ? "Failed to load commits" : undefined}
          />
        )}
        <Group justify="flex-end">
          <Button
            variant="default"
            size="xs"
            disabled={!changed}
            onClick={() => {
              setMode(policy.mode);
              setPinned(policy.pinnedCommit || policy.effectiveCommit || "");
            }}
          >
            Reset
          </Button>
          <Button
            size="xs"
            disabled={!changed || (mode === DeployMode.PINNED && !pinned)}
            loading={setPolicy.isPending}
            onClick={apply}
          >
            Apply
          </Button>
        </Group>
      </Stack>
    </Card>
  );
}

function CommitCell({ desired, applied }: { desired?: string; applied?: string }) {
  const drift = !!desired && desired !== applied;
  return (
    <Tooltip label={`desired ${desired || "none"} / applied ${applied || "none"}`} withArrow>
      <Text size="sm" ff="monospace" c={drift ? "orange" : undefined}>
        {shortCommit(applied) || "-"}
        {drift && ` → ${shortCommit(desired)}`}
      </Text>
    </Tooltip>
  );
}

function SyncTable({ nodes, policies }: { nodes: Node[]; policies?: { rules?: DeployPolicy; config?: DeployPolicy } }) {
  if (nodes.length === 0) return <Empty>No nodes registered.</Empty>;
  return (
    <Table.ScrollContainer minWidth={1000}>
      <Table verticalSpacing="xs" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Node</Table.Th>
            <Table.Th>Status</Table.Th>
            <Table.Th>Generation</Table.Th>
            <Table.Th>Rules (applied → desired)</Table.Th>
            <Table.Th>Config (applied → desired)</Table.Th>
            <Table.Th>Sync</Table.Th>
            <Table.Th>Last apply</Table.Th>
            <Table.Th>Message</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {nodes.map((n) => {
            const d = n.deploy;
            const rulesBehind =
              policies?.rules?.effectiveCommit && d?.desiredBundle?.rulesCommit !== policies.rules.effectiveCommit;
            return (
              <Table.Tr key={n.id}>
                <Table.Td>
                  <Anchor component={Link} to={`/nodes/${encodeURIComponent(n.id)}?tab=deploy`} fw={600}>
                    {n.id}
                  </Anchor>
                </Table.Td>
                <Table.Td>
                  <OnlineBadge node={n} />
                </Table.Td>
                <Table.Td ff="monospace">
                  {String(d?.appliedGeneration ?? 0n)} / {String(d?.desiredGeneration ?? 0n)}
                </Table.Td>
                <Table.Td>
                  <CommitCell desired={d?.desiredBundle?.rulesCommit} applied={d?.appliedBundle?.rulesCommit} />
                  {rulesBehind && !d?.desiredError && (
                    <Text size="xs" c="dimmed">
                      desired differs from policy
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <CommitCell desired={d?.desiredBundle?.configCommit} applied={d?.appliedBundle?.configCommit} />
                </Table.Td>
                <Table.Td>
                  <SyncBadge node={n} />
                </Table.Td>
                <Table.Td>
                  {d && <ApplyStatusBadge status={d.lastStatus} />}{" "}
                  {d?.lastReportAt && <TimeAgo ts={d.lastReportAt} size="xs" c="dimmed" />}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" lineClamp={2} maw={320} c={d?.desiredError ? "red" : undefined}>
                    {d?.desiredError || d?.lastMessage || "-"}
                  </Text>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

export default function DeployPage() {
  const policies = usePolicies(true);
  const nodes = useNodes();
  return (
    <>
      <PageHeader
        title="Deploy"
        description="Deployment policies for rules and config, and the sync state of every node"
      />
      {policies.isPending ? (
        <LoadingBlock />
      ) : policies.isError ? (
        <ErrorAlert error={policies.error} onRetry={() => policies.refetch()} />
      ) : (
        <SimpleGrid cols={{ base: 1, lg: 2 }} mb="md">
          {policies.data.rules && (
            <PolicyEditor
              key={`r:${policies.data.rules.mode}:${policies.data.rules.pinnedCommit}`}
              kind={DeployKind.RULES}
              policy={policies.data.rules}
            />
          )}
          {policies.data.config && (
            <PolicyEditor
              key={`c:${policies.data.config.mode}:${policies.data.config.pinnedCommit}`}
              kind={DeployKind.CONFIG}
              policy={policies.data.config}
            />
          )}
        </SimpleGrid>
      )}
      <Card withBorder padding="sm">
        <Title order={4} mb="sm" px={4}>
          Node sync overview
        </Title>
        {nodes.isPending ? (
          <LoadingBlock />
        ) : nodes.isError ? (
          <ErrorAlert error={nodes.error} onRetry={() => nodes.refetch()} />
        ) : (
          <SyncTable nodes={nodes.data} policies={policies.data} />
        )}
      </Card>
    </>
  );
}
