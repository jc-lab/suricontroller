import { useState } from "react";
import { Badge, Button, Card, Group, SegmentedControl, Table, Text, Tooltip } from "@mantine/core";
import { IconDeviceFloppy } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { api } from "../../api/client";
import type { Node } from "../../gen/suricontroller/api/v1/api_pb";
import { InterfaceMode } from "../../gen/suricontroller/agent/v1/agent_pb";
import { Empty } from "../../components/common";
import { interfaceModeLabel } from "../../lib/enums";

function modeColor(m: InterfaceMode): string {
  return m === InterfaceMode.IPS ? "red" : m === InterfaceMode.IDS ? "blue" : "gray";
}

function norm(m: InterfaceMode): InterfaceMode {
  return m === InterfaceMode.UNSPECIFIED ? InterfaceMode.OFF : m;
}

export function InterfacesPanel({ node }: { node: Node }) {
  const qc = useQueryClient();
  const [edits, setEdits] = useState<Record<string, InterfaceMode>>({});
  const value = (name: string, mode: InterfaceMode) => edits[name] ?? norm(mode);
  const dirty = node.interfaces.some((i) => edits[i.name] !== undefined && edits[i.name] !== norm(i.mode));

  const save = useMutation({
    mutationFn: () => {
      const modes: Record<string, InterfaceMode> = {};
      for (const i of node.interfaces) modes[i.name] = value(i.name, i.mode);
      return api.nodes.setInterfaceModes({ id: node.id, modes });
    },
    meta: { errorTitle: "Failed to set interface modes" },
    onSuccess: (r) => {
      setEdits({});
      if (r.node) qc.setQueryData(["node", node.id], r.node);
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      notifications.show({
        color: "green",
        message: node.online
          ? "Interface modes saved and pushed to the agent."
          : "Interface modes saved; they are applied when the node connects.",
      });
    },
  });

  if (node.interfaces.length === 0) {
    return (
      <Card withBorder>
        <Empty>
          The agent has not reported any manageable interfaces. Interfaces are configured in the agent's agent.yaml
          (<code>interfaces:</code>).
        </Empty>
      </Card>
    );
  }

  return (
    <Card withBorder padding={0}>
      <Table.ScrollContainer minWidth={760}>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Interface</Table.Th>
              <Table.Th>State</Table.Th>
              <Table.Th>Addresses</Table.Th>
              <Table.Th>Applied</Table.Th>
              <Table.Th>Desired mode</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {node.interfaces.map((i) => {
              const v = value(i.name, i.mode);
              const changed = v !== norm(i.mode);
              const pending = norm(i.mode) !== norm(i.appliedMode);
              return (
                <Table.Tr key={i.name}>
                  <Table.Td>
                    <Text fw={600} ff="monospace">
                      {i.name}
                    </Text>
                    {!i.ipsAllowed && (
                      <Text size="xs" c="dimmed">
                        IPS not allowed by the agent
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {!i.present ? (
                        <Badge color="red" variant="light" size="sm">
                          missing
                        </Badge>
                      ) : (
                        <Badge color={i.up ? "green" : "gray"} variant="light" size="sm">
                          {i.up ? "up" : "down"}
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" ff="monospace">
                      {i.addresses.join(", ") || "-"}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      <Badge color={modeColor(norm(i.appliedMode))} variant="light" size="sm">
                        {interfaceModeLabel(i.appliedMode)}
                      </Badge>
                      {pending && (
                        <Tooltip label={`Desired ${interfaceModeLabel(i.mode)} not applied yet`} withArrow>
                          <Badge color="yellow" variant="outline" size="xs">
                            pending
                          </Badge>
                        </Tooltip>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      <SegmentedControl
                        size="xs"
                        value={String(v)}
                        onChange={(s) => setEdits((e) => ({ ...e, [i.name]: Number(s) as InterfaceMode }))}
                        data={[
                          { value: String(InterfaceMode.OFF), label: "Off" },
                          { value: String(InterfaceMode.IDS), label: "IDS" },
                          {
                            value: String(InterfaceMode.IPS),
                            label: i.ipsAllowed ? "IPS" : "IPS (not allowed)",
                            disabled: !i.ipsAllowed,
                          },
                        ]}
                        color={modeColor(v)}
                      />
                      {changed && (
                        <Badge size="xs" color="blue" variant="dot">
                          changed
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      <Group justify="space-between" p="sm" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
        <Text size="xs" c="dimmed">
          Mode changes are applied immediately, independent of the deployment policy. IPS uses NFQUEUE (fail-open).
        </Text>
        <Group gap="xs">
          <Button variant="default" size="xs" disabled={!dirty} onClick={() => setEdits({})}>
            Reset
          </Button>
          <Button
            size="xs"
            leftSection={<IconDeviceFloppy size={14} />}
            disabled={!dirty}
            loading={save.isPending}
            onClick={() => save.mutate()}
          >
            Save
          </Button>
        </Group>
      </Group>
    </Card>
  );
}
