import { Anchor, Badge, Button, Card, Group, Table, Text, Title } from "@mantine/core";
import { IconEye } from "@tabler/icons-react";
import { Link } from "react-router";
import { Repo, useTree } from "../../api/hooks";
import type { Node } from "../../gen/suricontroller/api/v1/api_pb";
import { ErrorAlert, LoadingBlock } from "../../components/common";
import { CONFIG_FILES, CONFIG_FILE_HELP } from "../../lib/enums";
import { formatBytes } from "../../lib/format";

function fileLink(path: string) {
  return `/config?file=${encodeURIComponent(path)}`;
}

export function NodeConfigPanel({ node, onPreview }: { node: Node; onPreview: () => void }) {
  const tree = useTree(Repo.CONFIG);
  const sizes = new Map<string, bigint>();
  tree.data?.entries.forEach((e) => {
    if (!e.dir) sizes.set(e.path, e.size);
  });
  return (
    <Card withBorder padding={0}>
      <Group justify="space-between" p="sm">
        <div>
          <Title order={5}>Configuration layers</Title>
          <Text size="xs" c="dimmed">
            Files in <code>nodes/{node.id}/</code> override or extend <code>common/</code>. A node file starting with{" "}
            <code># suricontroller: replace</code> ignores the common file.
          </Text>
        </div>
        <Button size="xs" variant="light" leftSection={<IconEye size={14} />} onClick={onPreview}>
          Preview rendered config
        </Button>
      </Group>
      {tree.isPending ? (
        <LoadingBlock />
      ) : tree.isError ? (
        <ErrorAlert error={tree.error} onRetry={() => tree.refetch()} />
      ) : (
        <Table.ScrollContainer minWidth={700}>
          <Table verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>File</Table.Th>
                <Table.Th>common/</Table.Th>
                <Table.Th>nodes/{node.id}/</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {CONFIG_FILES.map((f) => {
                const common = `common/${f}`;
                const own = `nodes/${node.id}/${f}`;
                return (
                  <Table.Tr key={f}>
                    <Table.Td>
                      <Text size="sm" ff="monospace" fw={500}>
                        {f}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {CONFIG_FILE_HELP[f]}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {sizes.has(common) ? (
                        <Anchor component={Link} to={fileLink(common)} size="sm">
                          open ({formatBytes(sizes.get(common))})
                        </Anchor>
                      ) : (
                        <Text size="sm" c="dimmed">
                          not present
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      {sizes.has(own) ? (
                        <Group gap={6}>
                          <Badge size="xs" color="violet" variant="light">
                            override
                          </Badge>
                          <Anchor component={Link} to={fileLink(own)} size="sm">
                            open ({formatBytes(sizes.get(own))})
                          </Anchor>
                        </Group>
                      ) : (
                        <Anchor component={Link} to={fileLink(own)} size="sm" c="dimmed">
                          create override
                        </Anchor>
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
  );
}
