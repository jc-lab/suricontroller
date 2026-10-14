import { useMemo, useState } from "react";
import {
  Anchor,
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  Switch,
  Table,
  Text,
  Tooltip,
} from "@mantine/core";
import { IconDeviceFloppy } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { Link } from "react-router";
import { api } from "../../api/client";
import { useCollectionPolicies, useNodes } from "../../api/hooks";
import { errorMessage } from "../../api/errors";
import type { GetCollectionPoliciesResponse, Node } from "../../gen/suricontroller/api/v1/api_pb";
import { LogType } from "../../gen/suricontroller/agent/v1/agent_pb";
import { Empty, ErrorAlert, LoadingBlock } from "../../components/common";
import { EveTypesPicker } from "../../components/EveTypesPicker";
import { LOG_TYPES } from "../../lib/enums";
import {
  draftEquals,
  draftFromPolicy,
  eveSuggestions,
  policyInit,
  reportedEveTypes,
  toggleType,
  type PolicyDraft,
} from "../../lib/logPolicy";

const GLOBAL = "";

interface Row {
  inherit: boolean;
  draft: PolicyDraft;
}

type Rows = Record<string, Row>;

function initialRows(data: GetCollectionPoliciesResponse, nodes: Node[]): Rows {
  const rows: Rows = { [GLOBAL]: { inherit: false, draft: draftFromPolicy(data.global) } };
  for (const n of nodes) {
    const o = data.nodes[n.id];
    rows[n.id] = o ? { inherit: false, draft: draftFromPolicy(o) } : { inherit: true, draft: draftFromPolicy(data.global) };
  }
  return rows;
}

function rowChanged(a: Row | undefined, b: Row | undefined): boolean {
  if (!a || !b) return false;
  if (a.inherit !== b.inherit) return true;
  return !a.inherit && !draftEquals(a.draft, b.draft);
}

const ALL_TYPES = LOG_TYPES.map((t) => t.type);

function Matrix({ data, nodes }: { data: GetCollectionPoliciesResponse; nodes: Node[] }) {
  const qc = useQueryClient();
  const initial = useMemo(() => initialRows(data, nodes), [data, nodes]);
  const [rows, setRows] = useState<Rows>(initial);
  const [saving, setSaving] = useState(false);

  const keys = [GLOBAL, ...nodes.map((n) => n.id)];
  const effective = (k: string): PolicyDraft => {
    const r = rows[k] ?? initial[k]!;
    return r.inherit ? rows[GLOBAL]!.draft : r.draft;
  };
  const editable = keys.filter((k) => k === GLOBAL || !(rows[k]?.inherit ?? true));
  const changed = keys.filter((k) => rowChanged(rows[k], initial[k]));

  const update = (k: string, fn: (d: PolicyDraft) => PolicyDraft) =>
    setRows((r) => ({ ...r, [k]: { ...r[k]!, draft: fn(r[k]!.draft) } }));

  const setInherit = (k: string, inherit: boolean) =>
    setRows((r) => ({
      ...r,
      // Start a new override from the current global policy.
      [k]: { inherit, draft: inherit ? r[k]!.draft : initial[k]!.inherit ? r[GLOBAL]!.draft : r[k]!.draft },
    }));

  const columnState = (fn: (d: PolicyDraft) => boolean) => {
    const vals = editable.map((k) => fn(rows[k]!.draft));
    const all = vals.length > 0 && vals.every(Boolean);
    const some = vals.some(Boolean);
    return { all, some: some && !all };
  };
  const setColumn = (fn: (d: PolicyDraft, on: boolean) => PolicyDraft, on: boolean) =>
    setRows((r) => {
      const next = { ...r };
      for (const k of editable) next[k] = { ...next[k]!, draft: fn(next[k]!.draft, on) };
      return next;
    });

  const save = async () => {
    setSaving(true);
    const errors: string[] = [];
    for (const k of changed) {
      const row = rows[k]!;
      try {
        if (k === GLOBAL) {
          await api.logs.setGlobalCollectionPolicy({ policy: policyInit(row.draft) });
        } else {
          await api.logs.setNodeCollectionPolicy({
            nodeId: k,
            inherit: row.inherit,
            policy: row.inherit ? undefined : policyInit(row.draft),
          });
        }
      } catch (e) {
        errors.push(`${k === GLOBAL ? "Global" : k}: ${errorMessage(e)}`);
      }
    }
    setSaving(false);
    if (errors.length) {
      notifications.show({ color: "red", title: "Some policies were not saved", message: errors.join("\n"), autoClose: 10000 });
    } else {
      notifications.show({ color: "green", message: `Saved ${changed.length} collection polic${changed.length === 1 ? "y" : "ies"}` });
    }
    void qc.invalidateQueries({ queryKey: ["collectionPolicies"] });
    void qc.invalidateQueries({ queryKey: ["nodes"] });
  };

  const enabledCol = columnState((d) => d.enabled);
  const allGlobalEve = eveSuggestions(nodes, rows[GLOBAL]!.draft.eveTypes);

  return (
    <Card withBorder padding={0}>
      <Group
        justify="space-between"
        p="sm"
        wrap="nowrap"
        align="flex-start"
        style={{ borderBottom: "1px solid var(--mantine-color-default-border)" }}
      >
        <Text size="xs" c="dimmed" style={{ flex: 1 }}>
          Rows are the global default and every node; nodes either inherit the global policy or have their own.
          Column checkboxes in the header toggle a log type for all editable rows.
        </Text>
        <Group gap="xs" wrap="nowrap">
          {changed.length > 0 && (
            <Badge color="yellow" variant="light">
              {changed.length} unsaved
            </Badge>
          )}
          <Button variant="default" size="xs" disabled={!changed.length || saving} onClick={() => setRows(initial)}>
            Reset
          </Button>
          <Button
            size="xs"
            leftSection={<IconDeviceFloppy size={14} />}
            disabled={!changed.length}
            loading={saving}
            onClick={() => void save()}
          >
            Save
          </Button>
        </Group>
      </Group>
      <Table.ScrollContainer minWidth={1100}>
        <Table verticalSpacing="xs" striped withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Scope</Table.Th>
              <Table.Th>Inherit global</Table.Th>
              <Table.Th>
                <Group gap={6} wrap="nowrap">
                  <Checkbox
                    size="xs"
                    checked={enabledCol.all}
                    indeterminate={enabledCol.some}
                    onChange={(e) => setColumn((d, on) => ({ ...d, enabled: on }), e.currentTarget.checked)}
                    aria-label="Toggle collection for all rows"
                  />
                  Collect
                </Group>
              </Table.Th>
              {LOG_TYPES.map((t) => {
                const st = columnState((d) => d.types.includes(t.type));
                return (
                  <Table.Th key={t.type}>
                    <Tooltip label={`${t.description} — toggle for all editable rows`} withArrow>
                      <Group gap={6} wrap="nowrap">
                        <Checkbox
                          size="xs"
                          checked={st.all}
                          indeterminate={st.some}
                          onChange={(e) => setColumn((d, on) => toggleType(d, t.type, on), e.currentTarget.checked)}
                          aria-label={`Select ${t.label} for all rows`}
                        />
                        <Text size="sm" fw={600} style={{ whiteSpace: "nowrap" }}>
                          {t.label}
                        </Text>
                      </Group>
                    </Tooltip>
                  </Table.Th>
                );
              })}
              <Table.Th>EVE event types</Table.Th>
              <Table.Th>Row</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {keys.map((k) => {
              const row = rows[k]!;
              const node = nodes.find((n) => n.id === k);
              const d = effective(k);
              const locked = k !== GLOBAL && row.inherit;
              const available = new Set(node?.logSources.map((s) => s.type) ?? []);
              const dirty = rowChanged(row, initial[k]);
              return (
                <Table.Tr key={k || "__global"}>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      {k === GLOBAL ? (
                        <Text fw={700} size="sm">
                          Global default
                        </Text>
                      ) : (
                        <Anchor component={Link} to={`/nodes/${encodeURIComponent(k)}?tab=logs`} size="sm" fw={600}>
                          {k}
                        </Anchor>
                      )}
                      {node && !node.online && (
                        <Badge size="xs" color="gray" variant="dot">
                          offline
                        </Badge>
                      )}
                      {dirty && (
                        <Badge size="xs" color="yellow" variant="light">
                          changed
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    {k === GLOBAL ? (
                      <Text size="xs" c="dimmed">
                        -
                      </Text>
                    ) : (
                      <Switch size="xs" checked={row.inherit} onChange={(e) => setInherit(k, e.currentTarget.checked)} />
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Checkbox
                      size="sm"
                      checked={d.enabled}
                      disabled={locked}
                      onChange={(e) => {
                        const on = e.currentTarget.checked;
                        update(k, (x) => ({ ...x, enabled: on }));
                      }}
                      aria-label={`Collect logs for ${k || "global"}`}
                    />
                  </Table.Td>
                  {LOG_TYPES.map((t) => {
                    const missing = !!node && node.logSources.length > 0 && !available.has(t.type);
                    return (
                      <Table.Td key={t.type}>
                        <Group gap={4} wrap="nowrap">
                          <Checkbox
                            size="sm"
                            checked={d.types.includes(t.type)}
                            disabled={locked || !d.enabled}
                            onChange={(e) => {
                              const on = e.currentTarget.checked;
                              update(k, (x) => toggleType(x, t.type, on));
                            }}
                            aria-label={`${t.label} for ${k || "global"}`}
                          />
                          {missing && (
                            <Tooltip label="The node does not report this log source" withArrow>
                              <Text size="xs" c="dimmed">
                                n/a
                              </Text>
                            </Tooltip>
                          )}
                        </Group>
                      </Table.Td>
                    );
                  })}
                  <Table.Td>
                    <EveTypesPicker
                      draft={d}
                      disabled={locked || !d.enabled || !d.types.includes(LogType.EVE)}
                      suggestions={k === GLOBAL ? allGlobalEve : eveSuggestions(node, d.eveTypes)}
                      reported={k === GLOBAL ? nodes.flatMap((n) => reportedEveTypes(n.logSources)) : reportedEveTypes(node?.logSources ?? [])}
                      onChange={(nd) => update(k, () => nd)}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4} wrap="nowrap">
                      <Button
                        size="compact-xs"
                        variant="light"
                        disabled={locked}
                        onClick={() => update(k, (x) => ({ ...x, enabled: true, types: [...ALL_TYPES], eveAllTypes: true }))}
                      >
                        All
                      </Button>
                      <Button
                        size="compact-xs"
                        variant="light"
                        color="gray"
                        disabled={locked}
                        onClick={() => update(k, (x) => ({ ...x, types: [] }))}
                      >
                        None
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {nodes.length === 0 && <Empty>No nodes registered; only the global policy can be edited.</Empty>}
    </Card>
  );
}

export function CollectionMatrix() {
  const policies = useCollectionPolicies();
  const nodes = useNodes(false);
  if (policies.isPending || nodes.isPending) return <LoadingBlock />;
  if (policies.isError) return <ErrorAlert error={policies.error} onRetry={() => policies.refetch()} />;
  if (nodes.isError) return <ErrorAlert error={nodes.error} onRetry={() => nodes.refetch()} />;
  // Re-initialize the editor whenever the stored policies or the node set change.
  const key = JSON.stringify([
    policyInit(draftFromPolicy(policies.data.global)),
    Object.entries(policies.data.nodes)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [k, policyInit(draftFromPolicy(v))]),
    nodes.data.map((n) => n.id),
  ]);
  return <Matrix key={key} data={policies.data} nodes={nodes.data} />;
}
