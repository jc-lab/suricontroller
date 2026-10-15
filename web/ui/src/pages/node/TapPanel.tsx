import { useState } from "react";
import { Alert, Badge, Button, Card, Group, SegmentedControl, Stack, Table, Text, Tooltip } from "@mantine/core";
import { IconAlertTriangle, IconDeviceFloppy } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { api } from "../../api/client";
import type { Node } from "../../gen/suricontroller/api/v1/api_pb";
import { EndpointMode } from "../../gen/suricontroller/agent/v1/agent_pb";
import { Empty } from "../../components/common";
import { endpointModeLabel } from "../../lib/enums";

function modeColor(m: EndpointMode): string {
  return m === EndpointMode.PREVENT ? "red" : m === EndpointMode.DETECT ? "blue" : "gray";
}

function norm(m: EndpointMode): EndpointMode {
  return m === EndpointMode.UNSPECIFIED ? EndpointMode.OFF : m;
}

// TapPanel sets the inspection mode of the proxy endpoints (suritap) the
// agent declares. The agent writes them to the plugin's policy file and the
// proxies pick them up within seconds.
export function TapPanel({ node }: { node: Node }) {
  const qc = useQueryClient();
  const tap = node.tap;
  const endpoints = tap?.endpoints ?? [];
  const [edits, setEdits] = useState<Record<string, EndpointMode>>({});
  const value = (name: string, mode: EndpointMode) => edits[name] ?? norm(mode);
  const dirty = endpoints.some((e) => edits[e.name] !== undefined && edits[e.name] !== norm(e.mode));

  const save = useMutation({
    mutationFn: () => {
      const modes: Record<string, EndpointMode> = {};
      for (const e of endpoints) modes[e.name] = value(e.name, e.mode);
      return api.nodes.setEndpointModes({ id: node.id, modes });
    },
    meta: { errorTitle: "Failed to set endpoint modes" },
    onSuccess: (r) => {
      setEdits({});
      if (r.node) qc.setQueryData(["node", node.id], r.node);
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      notifications.show({
        color: "green",
        message: node.online
          ? "Endpoint modes saved and pushed to the agent."
          : "Endpoint modes saved; they are applied when the node connects.",
      });
    },
  });

  if (!tap || endpoints.length === 0) {
    return (
      <Card withBorder>
        <Empty>
          The agent has not declared any proxy endpoints. Enable the tap instance and list endpoints in the agent's
          agent.yaml (<code>tap: enabled, endpoints:</code>).
        </Empty>
      </Card>
    );
  }

  return (
    <Stack gap="sm">
      {!tap.enabled && (
        <Alert color="yellow" icon={<IconAlertTriangle size={16} />}>
          The tap instance is disabled in agent.yaml; endpoint modes have no effect until it is enabled.
        </Alert>
      )}
      {tap.enabled && !tap.pluginPresent && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />}>
          The suritap plugin is missing on the node; the tap instance cannot start.
        </Alert>
      )}
      <Card withBorder padding={0}>
        <Table.ScrollContainer minWidth={700}>
          <Table verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Endpoint</Table.Th>
                <Table.Th>Applied</Table.Th>
                <Table.Th>Desired mode</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {endpoints.map((e) => {
                const v = value(e.name, e.mode);
                const changed = v !== norm(e.mode);
                const pending = norm(e.mode) !== norm(e.appliedMode);
                return (
                  <Table.Tr key={e.name}>
                    <Table.Td>
                      <Text fw={600} ff="monospace">
                        {e.name}
                      </Text>
                      {e.description && (
                        <Text size="xs" c="dimmed">
                          {e.description}
                        </Text>
                      )}
                      {!e.preventAllowed && (
                        <Text size="xs" c="dimmed">
                          Prevent not allowed by the agent
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        <Badge color={modeColor(norm(e.appliedMode))} variant="light" size="sm">
                          {endpointModeLabel(e.appliedMode)}
                        </Badge>
                        {pending && (
                          <Tooltip label={`Desired ${endpointModeLabel(e.mode)} not applied yet`} withArrow>
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
                          onChange={(s) => setEdits((x) => ({ ...x, [e.name]: Number(s) as EndpointMode }))}
                          data={[
                            { value: String(EndpointMode.OFF), label: "Off" },
                            { value: String(EndpointMode.DETECT), label: "Detect" },
                            {
                              value: String(EndpointMode.PREVENT),
                              label: e.preventAllowed ? "Prevent" : "Prevent (not allowed)",
                              disabled: !e.preventAllowed,
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
            Off: not inspected. Detect: inspected, never blocked. Prevent: drop verdicts block (403). Applied without
            restarting Suricata; proxies follow within seconds.
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
    </Stack>
  );
}
