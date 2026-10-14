import { useState } from "react";
import {
  ActionIcon,
  Anchor,
  Button,
  Card,
  Group,
  Modal,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Textarea,
  Tooltip,
} from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { Link, useNavigate } from "react-router";
import { api } from "../api/client";
import { useNodes } from "../api/hooks";
import type { Node } from "../gen/suricontroller/api/v1/api_pb";
import { Empty, ErrorAlert, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import { OnlineBadge, SyncBadge } from "../components/badges";
import { useDeleteNode, useToggleNode } from "../components/nodeMutations";

function platformText(n: Node): string {
  const p = n.platform;
  if (!p) return "";
  const os = [p.osName, p.osVersion].filter(Boolean).join(" ");
  return [p.profile, os, p.arch].filter(Boolean).join(" · ");
}

function parseKeyLine(line: string): { ok: boolean; nodeId?: string; error?: string } {
  const parts = line.trim().split(/\s+/);
  if (!line.trim()) return { ok: false };
  if (parts[0] !== "ssh-ed25519") return { ok: false, error: 'The key must start with "ssh-ed25519"' };
  if (parts.length < 2 || !parts[1]!.startsWith("AAAA")) return { ok: false, error: "Missing base64 key data" };
  if (parts.length < 3) return { ok: false, error: "The key comment (node id) is missing" };
  return { ok: true, nodeId: parts.slice(2).join(" ") };
}

function AddNodeModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [key, setKey] = useState("");
  const [desc, setDesc] = useState("");
  const parsed = parseKeyLine(key);
  const add = useMutation({
    mutationFn: () => api.nodes.addNode({ publicKey: key.trim(), description: desc.trim() }),
    meta: { silent: true },
    onSuccess: (r) => {
      notifications.show({ color: "green", title: "Node added", message: `${r.node?.id} can now connect.` });
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      setKey("");
      setDesc("");
      onClose();
      if (r.node) navigate(`/nodes/${encodeURIComponent(r.node.id)}`);
    },
  });
  return (
    <Modal opened={opened} onClose={onClose} title="Add node" size="lg">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate();
        }}
      >
        <Stack>
          <Text size="sm" c="dimmed">
            Paste the agent public key line, printed by <code>suri-node-agent pubkey</code>. The key comment is the
            node id and must match <code>node_id</code> in agent.yaml.
          </Text>
          <Textarea
            label="Public key"
            placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... router-01"
            autosize
            minRows={3}
            styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } }}
            value={key}
            onChange={(e) => setKey(e.currentTarget.value)}
            error={parsed.error}
            description={parsed.ok ? `Node id: ${parsed.nodeId}` : undefined}
            required
            data-autofocus
          />
          <TextInput
            label="Description"
            placeholder="e.g. Office router"
            value={desc}
            onChange={(e) => setDesc(e.currentTarget.value)}
          />
          {add.isError && <ErrorAlert error={add.error} title="Could not add the node" />}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={add.isPending} disabled={!parsed.ok}>
              Add node
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

export default function NodesPage() {
  const nodes = useNodes();
  const [adding, setAdding] = useState(false);
  const toggle = useToggleNode();
  const del = useDeleteNode();

  return (
    <>
      <PageHeader
        title="Nodes"
        description="Registered Suricata nodes and their deployment state"
        right={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setAdding(true)}>
            Add node
          </Button>
        }
      />
      <AddNodeModal opened={adding} onClose={() => setAdding(false)} />
      <Card withBorder padding={0}>
        {nodes.isPending ? (
          <LoadingBlock />
        ) : nodes.isError ? (
          <ErrorAlert error={nodes.error} onRetry={() => nodes.refetch()} />
        ) : nodes.data.length === 0 ? (
          <Empty>No nodes yet. Click "Add node" and paste the agent's public key.</Empty>
        ) : (
          <Table.ScrollContainer minWidth={980}>
            <Table verticalSpacing="sm" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Node</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Agent</Table.Th>
                  <Table.Th>Suricata</Table.Th>
                  <Table.Th>Platform</Table.Th>
                  <Table.Th>Generation</Table.Th>
                  <Table.Th>Deploy</Table.Th>
                  <Table.Th>Last seen</Table.Th>
                  <Table.Th>Enabled</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {nodes.data.map((n) => (
                  <Table.Tr key={n.id}>
                    <Table.Td>
                      <Anchor component={Link} to={`/nodes/${encodeURIComponent(n.id)}`} fw={600}>
                        {n.id}
                      </Anchor>
                      {n.description && (
                        <Text size="xs" c="dimmed" lineClamp={1}>
                          {n.description}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <OnlineBadge node={n} />
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{n.agentVersion || "-"}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{n.engine?.version || "-"}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" lineClamp={1}>
                        {platformText(n) || "-"}
                      </Text>
                      {n.platform?.hostname && (
                        <Text size="xs" c="dimmed">
                          {n.platform.hostname}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label="applied / desired generation" withArrow>
                        <Text size="sm" ff="monospace">
                          {String(n.deploy?.appliedGeneration ?? 0n)} / {String(n.deploy?.desiredGeneration ?? 0n)}
                        </Text>
                      </Tooltip>
                    </Table.Td>
                    <Table.Td>
                      <SyncBadge node={n} />
                    </Table.Td>
                    <Table.Td>
                      {n.online ? (
                        <Text size="sm" c="green">
                          now
                        </Text>
                      ) : (
                        <TimeAgo ts={n.lastSeenAt} />
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Switch
                        checked={n.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === n.id}
                        onChange={(e) => toggle.mutate({ id: n.id, enabled: e.currentTarget.checked })}
                        aria-label={`Enable ${n.id}`}
                      />
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label="Delete node" withArrow>
                        <ActionIcon variant="subtle" color="red" onClick={() => del.confirm(n.id)}>
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Tooltip>
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
