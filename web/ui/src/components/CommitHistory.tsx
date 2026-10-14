import { useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Drawer,
  Group,
  ScrollArea,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconPlayerPlay, IconRocket } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useCommitHistory, usePolicies } from "../api/hooks";
import { DeployKind, DeployMode, Repo } from "../gen/suricontroller/api/v1/api_pb";
import type { Commit, DeployPolicy, FileChangeStat } from "../gen/suricontroller/api/v1/api_pb";
import { deployKindLabel, deployModeLabel } from "../lib/enums";
import { firstLine, formatDateTime, shortCommit, tsDate } from "../lib/format";
import { CommitId, CopyText, Empty, ErrorAlert, InfoGrid, LoadingBlock, TimeAgo } from "./common";
import { DeployModeBadge } from "./badges";
import { DiffView } from "./DiffView";
import { useDeployActions } from "./deployActions";

const BIG_DIFF_LINES = 20_000;

function actionColor(a: string): string {
  return a === "added" ? "green" : a === "deleted" ? "red" : "blue";
}

function CommitBadges({ id, head, policy }: { id: string; head?: string; policy?: DeployPolicy }) {
  return (
    <Group gap={4} wrap="nowrap">
      {id === head && (
        <Badge size="xs" variant="outline" color="gray">
          HEAD
        </Badge>
      )}
      {policy && id === policy.effectiveCommit && (
        <Tooltip label="Commit deployed to nodes (effective)" withArrow>
          <Badge size="xs" color="green" variant="light">
            deployed
          </Badge>
        </Tooltip>
      )}
      {policy && policy.mode === DeployMode.PINNED && id === policy.pinnedCommit && (
        <Badge size="xs" color="violet" variant="light">
          pinned
        </Badge>
      )}
    </Group>
  );
}

function FileStats({ files, selected, onSelect }: { files: FileChangeStat[]; selected: string; onSelect: (p: string) => void }) {
  return (
    <Table verticalSpacing={4} fz="sm" highlightOnHover>
      <Table.Tbody>
        {files.map((f) => (
          <Table.Tr
            key={f.path}
            className="clickable-row"
            onClick={() => onSelect(selected === f.path ? "" : f.path)}
            bg={selected === f.path ? "var(--mantine-color-default-hover)" : undefined}
          >
            <Table.Td w={90}>
              <Badge size="xs" variant="light" color={actionColor(f.action)}>
                {f.action}
              </Badge>
            </Table.Td>
            <Table.Td>
              <Text size="sm" ff="monospace" style={{ wordBreak: "break-all" }}>
                {f.path}
              </Text>
            </Table.Td>
            <Table.Td w={120} ta="right">
              <Text span size="xs" c="green" ff="monospace">
                +{f.additions}
              </Text>{" "}
              <Text span size="xs" c="red" ff="monospace">
                -{f.deletions}
              </Text>
            </Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}

export function CommitDetail(props: {
  repo: Repo;
  kind: DeployKind;
  id: string;
  head?: string;
  policy?: DeployPolicy;
}) {
  const { repo, id } = props;
  const [path, setPath] = useState("");
  const [forceFull, setForceFull] = useState(false);
  const { deployCommit } = useDeployActions(props.kind);
  const detail = useQuery({
    queryKey: ["commit", repo, id],
    queryFn: () => api.repo.getCommit({ repo, id }),
    staleTime: Infinity,
  });
  const totalLines = detail.data?.files.reduce((a, f) => a + f.additions + f.deletions, 0) ?? 0;
  const big = totalLines > BIG_DIFF_LINES;
  const wantDiff = !!detail.data && (!!path || !big || forceFull);
  const diff = useQuery({
    queryKey: ["diff", repo, id, path],
    queryFn: () => api.repo.diff({ repo, to: id, path }),
    enabled: wantDiff,
    staleTime: Infinity,
  });
  if (detail.isPending) return <LoadingBlock />;
  if (detail.isError) return <ErrorAlert error={detail.error} />;
  const c = detail.data.commit;
  return (
    <Stack>
      <Card withBorder padding="sm">
        <Text fw={600} style={{ whiteSpace: "pre-wrap" }}>
          {c?.message.trim()}
        </Text>
        <InfoGrid
          labelWidth={90}
          items={[
            ["Commit", <CopyText value={id} />],
            ["Author", c?.author || "-"],
            ["Date", formatDateTime(tsDate(c?.time))],
            ["Parents", c?.parents.length ? c.parents.map((p) => shortCommit(p)).join(", ") : "none (initial commit)"],
            ["Status", <CommitBadges id={id} head={props.head} policy={props.policy} />],
          ]}
        />
        <Group mt="sm">
          <Button
            size="xs"
            leftSection={<IconRocket size={14} />}
            variant="light"
            disabled={props.policy?.mode === DeployMode.PINNED && props.policy.pinnedCommit === id}
            onClick={() => deployCommit(id, firstLine(c?.message))}
          >
            Deploy this commit
          </Button>
        </Group>
      </Card>
      <div>
        <Group justify="space-between" mb={4}>
          <Title order={6}>Changed files ({detail.data.files.length})</Title>
          {path && (
            <Anchor size="xs" onClick={() => setPath("")}>
              Show all files
            </Anchor>
          )}
        </Group>
        <Card withBorder padding={0}>
          <ScrollArea.Autosize mah={240}>
            <FileStats files={detail.data.files} selected={path} onSelect={setPath} />
          </ScrollArea.Autosize>
        </Card>
      </div>
      <div>
        <Title order={6} mb={4}>
          Diff {path && <Text span ff="monospace" size="sm">({path})</Text>}
        </Title>
        {!wantDiff ? (
          <Alert color="blue">
            This commit changes {totalLines.toLocaleString()} lines. Select a file above to view its diff, or{" "}
            <Anchor onClick={() => setForceFull(true)}>load the full diff</Anchor>.
          </Alert>
        ) : diff.isPending ? (
          <LoadingBlock />
        ) : diff.isError ? (
          <ErrorAlert error={diff.error} />
        ) : (
          <DiffView diff={diff.data.unifiedDiff} maxHeight="calc(100vh - 480px)" />
        )}
      </div>
    </Stack>
  );
}

/** Paginated commit history with diffs and deploy actions. */
export function CommitHistory(props: { repo: Repo; kind: DeployKind; title?: string }) {
  const { repo, kind } = props;
  const history = useCommitHistory(repo);
  const policies = usePolicies();
  const policy = kind === DeployKind.RULES ? policies.data?.rules : policies.data?.config;
  const { deployCommit, resumeAuto, setPolicy } = useDeployActions(kind);
  const [selected, setSelected] = useState<string | null>(null);
  const commits: Commit[] = history.data?.pages.flatMap((p) => p.commits) ?? [];
  const head = history.data?.pages[0]?.head;

  return (
    <Stack>
      <Card withBorder padding="sm">
        <Group justify="space-between" wrap="wrap">
          <Group gap="sm">
            <Text fw={600}>{deployKindLabel(kind)} deployment</Text>
            <DeployModeBadge policy={policy} />
            {policy && (
              <Text size="sm" c="dimmed">
                effective <CommitId id={policy.effectiveCommit} /> · head <CommitId id={policy.headCommit} />
              </Text>
            )}
          </Group>
          {policy && policy.mode !== DeployMode.AUTO && (
            <Button
              size="xs"
              variant="light"
              color="green"
              leftSection={<IconPlayerPlay size={14} />}
              onClick={resumeAuto}
              loading={setPolicy.isPending}
            >
              Resume auto ({deployModeLabel(policy.mode).toLowerCase()} now)
            </Button>
          )}
        </Group>
      </Card>
      <Card withBorder padding={0}>
        {history.isPending ? (
          <LoadingBlock />
        ) : history.isError ? (
          <ErrorAlert error={history.error} onRetry={() => history.refetch()} />
        ) : commits.length === 0 ? (
          <Empty>No commits yet.</Empty>
        ) : (
          <Table.ScrollContainer minWidth={760}>
            <Table verticalSpacing="xs" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Commit</Table.Th>
                  <Table.Th>Message</Table.Th>
                  <Table.Th>Author</Table.Th>
                  <Table.Th>When</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {commits.map((c) => (
                  <Table.Tr key={c.id} className="clickable-row" onClick={() => setSelected(c.id)}>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <Text size="sm" ff="monospace">
                          {shortCommit(c.id)}
                        </Text>
                        <CommitBadges id={c.id} head={head} policy={policy} />
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" lineClamp={1}>
                        {firstLine(c.message)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{c.author}</Text>
                    </Table.Td>
                    <Table.Td>
                      <TimeAgo ts={c.time} />
                    </Table.Td>
                    <Table.Td onClick={(e) => e.stopPropagation()}>
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        leftSection={<IconRocket size={12} />}
                        disabled={policy?.mode === DeployMode.PINNED && policy.pinnedCommit === c.id}
                        onClick={() => deployCommit(c.id, firstLine(c.message))}
                      >
                        Deploy
                      </Button>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {history.hasNextPage && (
          <Button
            variant="subtle"
            fullWidth
            onClick={() => void history.fetchNextPage()}
            loading={history.isFetchingNextPage}
          >
            Load older commits
          </Button>
        )}
      </Card>
      <Drawer
        opened={!!selected}
        onClose={() => setSelected(null)}
        position="right"
        size="min(1100px, 100%)"
        title={selected ? `Commit ${shortCommit(selected)}` : ""}
      >
        {selected && <CommitDetail repo={repo} kind={kind} id={selected} head={head} policy={policy} />}
      </Drawer>
    </Stack>
  );
}
