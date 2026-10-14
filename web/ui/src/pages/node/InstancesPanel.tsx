import { Alert, Badge, Card, Group, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import type { Node } from "../../gen/suricontroller/api/v1/api_pb";
import { Empty, InfoGrid } from "../../components/common";
import { formatBytes, formatDuration, formatNumber } from "../../lib/format";

export function InstancesPanel({ node }: { node: Node }) {
  if (node.instances.length === 0) {
    return (
      <Card withBorder>
        <Empty>{node.online ? "No Suricata instances are running." : "Instance status is only available while the node is online."}</Empty>
      </Card>
    );
  }
  return (
    <SimpleGrid cols={{ base: 1, lg: 2 }}>
      {node.instances.map((ins) => {
        const counters = Object.entries(ins.counters).sort(([a], [b]) => a.localeCompare(b));
        return (
          <Card withBorder key={ins.name}>
            <Group justify="space-between" mb="sm">
              <Group gap="xs">
                <Title order={5}>{ins.name}</Title>
                <Badge variant="outline" size="sm" color="gray">
                  {ins.capture}
                </Badge>
              </Group>
              <Badge color={ins.running ? "green" : "red"} variant="light">
                {ins.running ? "running" : "stopped"}
              </Badge>
            </Group>
            <Stack gap="sm">
              <InfoGrid
                labelWidth={130}
                items={[
                  ["Uptime", ins.running ? formatDuration(ins.uptimeSeconds) : "-"],
                  ["Memory (RSS)", formatBytes(ins.rssBytes)],
                  ["Interfaces", ins.interfaces.join(", ") || "-"],
                  [
                    "Rules",
                    <Text size="sm" span>
                      {formatNumber(ins.rulesLoaded)} loaded
                      {ins.rulesFailed > 0 && (
                        <Text span c="red" size="sm">
                          {" "}
                          · {formatNumber(ins.rulesFailed)} failed
                        </Text>
                      )}
                    </Text>,
                  ],
                ]}
              />
              {ins.lastError && (
                <Alert color="red" p="xs">
                  <Text size="xs" style={{ whiteSpace: "pre-wrap" }}>
                    {ins.lastError}
                  </Text>
                </Alert>
              )}
              {counters.length > 0 && (
                <Table withTableBorder striped verticalSpacing={4} fz="xs">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Counter</Table.Th>
                      <Table.Th ta="right">Value</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {counters.map(([k, v]) => (
                      <Table.Tr key={k}>
                        <Table.Td ff="monospace">{k}</Table.Td>
                        <Table.Td ta="right" ff="monospace">
                          {formatNumber(v)}
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              )}
            </Stack>
          </Card>
        );
      })}
    </SimpleGrid>
  );
}
