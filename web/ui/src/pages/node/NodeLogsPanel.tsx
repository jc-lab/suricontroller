import { useState } from "react";
import { Anchor, Badge, Button, Card, Checkbox, Group, SimpleGrid, Stack, Switch, Table, Text, Title } from "@mantine/core";
import { IconDeviceFloppy } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { Link } from "react-router";
import { api } from "../../api/client";
import { useCollectionPolicies } from "../../api/hooks";
import type { Node } from "../../gen/suricontroller/api/v1/api_pb";
import type { LogCollectionPolicy } from "../../gen/suricontroller/agent/v1/agent_pb";
import { LogType } from "../../gen/suricontroller/agent/v1/agent_pb";
import { Empty, ErrorAlert, LoadingBlock } from "../../components/common";
import { EveTypesEditor } from "../../components/EveTypesPicker";
import { LOG_TYPES, logTypeLabel } from "../../lib/enums";
import { draftEquals, draftFromPolicy, eveSuggestions, policyInit, reportedEveTypes, toggleType, type PolicyDraft } from "../../lib/logPolicy";

function PolicyForm(props: {
  draft: PolicyDraft;
  node: Node;
  disabled?: boolean;
  onChange: (d: PolicyDraft) => void;
}) {
  const { draft, node, disabled, onChange } = props;
  const available = new Set(node.logSources.map((s) => s.type));
  return (
    <Stack gap="sm">
      <Switch
        label="Collect logs from this node"
        checked={draft.enabled}
        disabled={disabled}
        onChange={(e) => onChange({ ...draft, enabled: e.currentTarget.checked })}
      />
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xs">
        {LOG_TYPES.map((t) => (
          <Checkbox
            key={t.type}
            label={
              <span>
                {t.label}{" "}
                {node.logSources.length > 0 && !available.has(t.type) && (
                  <Text span size="xs" c="dimmed">
                    (no source reported)
                  </Text>
                )}
              </span>
            }
            description={t.description}
            checked={draft.types.includes(t.type)}
            disabled={disabled || !draft.enabled}
            onChange={(e) => onChange(toggleType(draft, t.type, e.currentTarget.checked))}
          />
        ))}
      </SimpleGrid>
      {draft.types.includes(LogType.EVE) && (
        <Card withBorder padding="sm">
          <Text size="sm" fw={600} mb="xs">
            EVE event types
          </Text>
          <EveTypesEditor
            draft={draft}
            disabled={disabled || !draft.enabled}
            suggestions={eveSuggestions(node, draft.eveTypes)}
            reported={reportedEveTypes(node.logSources)}
            onChange={onChange}
          />
        </Card>
      )}
    </Stack>
  );
}

function OverrideEditor(props: { node: Node; global?: LogCollectionPolicy; override?: LogCollectionPolicy }) {
  const { node } = props;
  const qc = useQueryClient();
  const initialInherit = !props.override;
  const initialDraft = draftFromPolicy(props.override ?? props.global);
  const [inherit, setInherit] = useState(initialInherit);
  const [draft, setDraft] = useState<PolicyDraft>(initialDraft);
  const dirty = inherit !== initialInherit || (!inherit && !draftEquals(draft, initialDraft));
  const save = useMutation({
    mutationFn: () =>
      api.logs.setNodeCollectionPolicy({
        nodeId: node.id,
        inherit,
        policy: inherit ? undefined : policyInit(draft),
      }),
    meta: { errorTitle: "Failed to save the log collection policy" },
    onSuccess: () => {
      notifications.show({ color: "green", message: `Log collection policy of ${node.id} saved` });
      void qc.invalidateQueries({ queryKey: ["collectionPolicies"] });
      void qc.invalidateQueries({ queryKey: ["node", node.id] });
    },
  });
  const shown = inherit ? draftFromPolicy(props.global) : draft;
  return (
    <Card withBorder>
      <Group justify="space-between" mb="sm">
        <Title order={5}>Log collection</Title>
        <Anchor component={Link} to="/logs?tab=collection" size="xs">
          Edit all nodes
        </Anchor>
      </Group>
      <Stack>
        <Switch
          label="Inherit the global policy"
          description={inherit ? "This node uses the global collection policy." : "This node has its own policy."}
          checked={inherit}
          onChange={(e) => {
            const v = e.currentTarget.checked;
            setInherit(v);
            if (!v && initialInherit) setDraft(draftFromPolicy(props.global));
          }}
        />
        <PolicyForm draft={shown} node={node} disabled={inherit} onChange={setDraft} />
        <Group justify="flex-end">
          <Button
            variant="default"
            size="xs"
            disabled={!dirty}
            onClick={() => {
              setInherit(initialInherit);
              setDraft(initialDraft);
            }}
          >
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
      </Stack>
    </Card>
  );
}

export function NodeLogsPanel({ node }: { node: Node }) {
  const policies = useCollectionPolicies();
  const override = policies.data?.nodes[node.id];
  const editorKey = JSON.stringify([
    !!override,
    override ? policyInit(draftFromPolicy(override)) : null,
    policies.data?.global ? policyInit(draftFromPolicy(policies.data.global)) : null,
  ]);
  return (
    <Stack>
      <Card withBorder padding={0}>
        <Group justify="space-between" p="sm">
          <Title order={5}>Log sources reported by the agent</Title>
          <Anchor component={Link} to={`/logs?tab=browser&node=${encodeURIComponent(node.id)}`} size="xs">
            Browse stored logs
          </Anchor>
        </Group>
        {node.logSources.length === 0 ? (
          <Empty>No log sources reported.</Empty>
        ) : (
          <Table.ScrollContainer minWidth={600}>
            <Table verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Type</Table.Th>
                  <Table.Th>Instance</Table.Th>
                  <Table.Th>Path</Table.Th>
                  <Table.Th>EVE event types</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {node.logSources.map((s, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>
                      <Badge variant="light" size="sm">
                        {logTypeLabel(s.type)}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{s.instance || "-"}</Table.Td>
                    <Table.Td>
                      <Text size="xs" ff="monospace">
                        {s.path}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {s.eveTypes.map((t) => (
                          <Badge key={t} size="xs" variant="outline" color="gray">
                            {t}
                          </Badge>
                        ))}
                        {s.type === LogType.EVE && s.eveTypes.length === 0 && (
                          <Text size="xs" c="dimmed">
                            unknown
                          </Text>
                        )}
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>
      {policies.isPending ? (
        <LoadingBlock />
      ) : policies.isError ? (
        <ErrorAlert error={policies.error} onRetry={() => policies.refetch()} />
      ) : (
        <OverrideEditor key={editorKey} node={node} global={policies.data.global} override={override} />
      )}
    </Stack>
  );
}
