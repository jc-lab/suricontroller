import { Anchor, Badge, Button, Card, Group, Select, Stack, Table, Text, Title, Tooltip } from "@mantine/core";
import { IconDownload, IconRefresh } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router";
import { api, logDownloadUrl } from "../../api/client";
import { useNodes } from "../../api/hooks";
import { LogType } from "../../gen/suricontroller/agent/v1/agent_pb";
import { Empty, ErrorAlert, LoadingBlock, TimeAgo } from "../../components/common";
import { LOG_TYPES, logTypeLabel } from "../../lib/enums";
import { formatBytes } from "../../lib/format";
import { LogTail } from "./LogTail";

function FileList({ nodeId, type }: { nodeId: string; type: LogType }) {
  const files = useQuery({
    queryKey: ["logFiles", nodeId, type],
    queryFn: () => api.logs.listLogFiles({ nodeId, type }),
    refetchInterval: 30_000,
  });
  return (
    <Card withBorder padding={0}>
      <Group justify="space-between" p="sm">
        <Title order={5}>Stored files</Title>
        <Group gap="xs">
          {files.data && (
            <Text size="sm" c="dimmed">
              {files.data.files.length} file(s), {formatBytes(files.data.totalBytes)}
            </Text>
          )}
          <Tooltip label="Refresh" withArrow>
            <Button size="compact-xs" variant="subtle" onClick={() => void files.refetch()} loading={files.isFetching}>
              <IconRefresh size={14} />
            </Button>
          </Tooltip>
        </Group>
      </Group>
      {files.isPending ? (
        <LoadingBlock />
      ) : files.isError ? (
        <ErrorAlert error={files.error} onRetry={() => files.refetch()} />
      ) : files.data.files.length === 0 ? (
        <Empty>No stored log files for this selection.</Empty>
      ) : (
        <Table.ScrollContainer minWidth={700} mah={360} type="native">
          <Table verticalSpacing={6} striped stickyHeader>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>File</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th ta="right">Size</Table.Th>
                <Table.Th>Modified</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {[...files.data.files].reverse().map((f) => (
                <Table.Tr key={f.path}>
                  <Table.Td>
                    <Group gap={6}>
                      <Text size="sm" ff="monospace">
                        {f.path}
                      </Text>
                      {f.compressed && (
                        <Badge size="xs" variant="light" color="gray">
                          zstd
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>{logTypeLabel(f.type)}</Table.Td>
                  <Table.Td ta="right">{formatBytes(f.size)}</Table.Td>
                  <Table.Td>
                    <TimeAgo ts={f.modTime} />
                  </Table.Td>
                  <Table.Td>
                    <Anchor href={logDownloadUrl(f.nodeId || nodeId, f.path)} download size="sm">
                      <Group gap={4} wrap="nowrap">
                        <IconDownload size={14} />
                        Download
                      </Group>
                    </Anchor>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Card>
  );
}

export function BrowserPanel() {
  const nodes = useNodes(false);
  const [params, setParams] = useSearchParams();
  const nodeId = params.get("node") ?? "";
  const type = Number(params.get("type") ?? LogType.EVE) as LogType;
  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params);
    p.set(k, v);
    setParams(p, { replace: true });
  };
  if (nodes.isPending) return <LoadingBlock />;
  if (nodes.isError) return <ErrorAlert error={nodes.error} onRetry={() => nodes.refetch()} />;
  const valid = nodes.data.some((n) => n.id === nodeId);
  return (
    <Stack>
      <Group align="flex-end">
        <Select
          label="Node"
          placeholder="Select a node"
          data={nodes.data.map((n) => ({ value: n.id, label: n.id }))}
          value={valid ? nodeId : null}
          onChange={(v) => v && set("node", v)}
          searchable
          w={260}
          nothingFoundMessage="No nodes"
        />
        <Select
          label="Log type"
          data={[
            { value: String(LogType.UNSPECIFIED), label: "All types (files only)" },
            ...LOG_TYPES.map((t) => ({ value: String(t.type), label: t.label })),
          ]}
          value={String(type)}
          onChange={(v) => v && set("type", v)}
          allowDeselect={false}
          w={220}
        />
      </Group>
      {!valid ? (
        <Card withBorder>
          <Empty>Select a node to browse its stored logs.</Empty>
        </Card>
      ) : (
        <>
          <FileList nodeId={nodeId} type={type} />
          {type === LogType.UNSPECIFIED ? (
            <Text size="sm" c="dimmed">
              Select a specific log type to tail it live.
            </Text>
          ) : (
            <LogTail key={`${nodeId}:${type}`} nodeId={nodeId} type={type} />
          )}
        </>
      )}
    </Stack>
  );
}
