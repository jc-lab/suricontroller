import { useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Grid,
  Group,
  Modal,
  NavLink,
  NumberInput,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { IconFile, IconFolder, IconPencil, IconPlus, IconRefresh } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { useSearchParams } from "react-router";
import { api } from "../api/client";
import { Repo, useProviders, useTree } from "../api/hooks";
import { DeployKind } from "../gen/suricontroller/api/v1/api_pb";
import type { Provider } from "../gen/suricontroller/api/v1/api_pb";
import { CommitId, Empty, ErrorAlert, LoadingBlock, PageHeader, TimeAgo } from "../components/common";
import { CommitHistory } from "../components/CommitHistory";
import { FileEditor } from "../components/FileEditor";
import { formatBytes, formatDuration, shortCommit } from "../lib/format";
import { useDirtyGuard } from "../lib/useDirtyGuard";
import { NEW_RULES_TEMPLATE } from "../lib/templates";

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

const UNITS = [
  { value: "60", label: "minutes" },
  { value: "3600", label: "hours" },
  { value: "86400", label: "days" },
];

function splitInterval(seconds: number): { value: number; unit: string } {
  if (seconds > 0 && seconds % 86400 === 0) return { value: seconds / 86400, unit: "86400" };
  if (seconds > 0 && seconds % 3600 === 0) return { value: seconds / 3600, unit: "3600" };
  return { value: Math.round(seconds / 60), unit: "60" };
}

// Masked value the API returns for secret options (rules.MaskedSecret).
const MASKED_SECRET = "********";

const SNORT_RULESETS = [
  { value: "auto", label: "Auto: subscription of the oinkcode, community without one" },
  { value: "registered", label: "snortrules-snapshot (Registered / Subscriber)" },
  { value: "lightspd", label: "Talos LightSPD package" },
  { value: "community", label: "Community (no oinkcode)" },
];

const SNORT_POLICIES = [
  { value: "connectivity", label: "Connectivity over security" },
  { value: "balanced", label: "Balanced (Talos default)" },
  { value: "security", label: "Security over connectivity" },
  { value: "max-detect", label: "Maximum detection" },
  { value: "all", label: "All rules" },
];

const SNORT_APPROX = [
  { value: "include", label: "Include (marked with a comment)" },
  { value: "exclude", label: "Exclude (listed in the report)" },
];

function ProviderEditModal({ provider, onClose }: { provider: Provider | null; onClose: () => void }) {
  return (
    <Modal opened={!!provider} onClose={onClose} title={provider ? `Provider ${provider.name}` : ""}>
      {provider && <ProviderEditForm provider={provider} onClose={onClose} />}
    </Modal>
  );
}

function ProviderEditForm({ provider, onClose }: { provider: Provider; onClose: () => void }) {
  const qc = useQueryClient();
  const init = splitInterval(provider.intervalSeconds);
  const [interval, setInterval] = useState<number>(init.value);
  const [unit, setUnit] = useState(init.unit);
  const [version, setVersion] = useState(provider.options["suricata_version"] ?? "");
  const [url, setUrl] = useState(provider.options["url"] ?? "");
  const snort = provider.type === "snort";
  const hasOinkcode = provider.options["oinkcode"] === MASKED_SECRET;
  // Empty keeps the stored oinkcode; clearOinkcode removes it.
  const [oinkcode, setOinkcode] = useState("");
  const [clearOinkcode, setClearOinkcode] = useState(false);
  const [ruleset, setRuleset] = useState(provider.options["ruleset"] || "auto");
  const [policy, setPolicy] = useState(provider.options["policy"] || "balanced");
  const [snortVersion, setSnortVersion] = useState(provider.options["snort_version"] ?? "");
  const [approx, setApprox] = useState(provider.options["approx"] || "include");
  const oinkcodeError =
    oinkcode !== "" && !/^[0-9a-fA-F]{40}$/.test(oinkcode.trim()) ? "40 hexadecimal characters" : undefined;
  const seconds = Math.round(interval * Number(unit));
  const save = useMutation({
    mutationFn: () => {
      const options: Record<string, string> = {};
      if (provider.type === "et-open") {
        if (version.trim() !== (provider.options["suricata_version"] ?? "")) options["suricata_version"] = version.trim();
      }
      if (snort) {
        if (clearOinkcode) options["oinkcode"] = "";
        else if (oinkcode.trim() !== "") options["oinkcode"] = oinkcode.trim();
        const changed = (k: string, v: string, def: string) => {
          if (v !== (provider.options[k] || def)) options[k] = v;
        };
        changed("ruleset", ruleset, "auto");
        changed("policy", policy, "balanced");
        changed("approx", approx, "include");
        if (snortVersion.trim() !== (provider.options["snort_version"] ?? "")) options["snort_version"] = snortVersion.trim();
      } else if (provider.fetches && url.trim() !== (provider.options["url"] ?? "")) {
        options["url"] = url.trim();
      }
      return api.rules.updateProvider({
        name: provider.name,
        intervalSeconds: provider.fetches ? seconds : undefined,
        options,
      });
    },
    meta: { silent: true },
    onSuccess: () => {
      notifications.show({ color: "green", message: `Provider ${provider.name} updated` });
      void qc.invalidateQueries({ queryKey: ["providers"] });
      onClose();
    },
  });
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <Stack>
        <Text size="sm" c="dimmed">
          Type: <b>{provider.type}</b>
        </Text>
        {provider.fetches && (
          <Group align="flex-end" grow>
            <NumberInput
              label="Update interval"
              min={1}
              value={interval}
              onChange={(v) => setInterval(Number(v) || 0)}
              description={`Every ${formatDuration(seconds)} (minimum 10 minutes)`}
              error={seconds < 600 ? "Must be at least 10 minutes" : undefined}
            />
            <Select data={UNITS} value={unit} onChange={(v) => setUnit(v ?? "3600")} allowDeselect={false} />
          </Group>
        )}
        {provider.type === "et-open" && (
          <TextInput
            label="Suricata version"
            description="Selects the ET Open ruleset (suricata-<version>). Empty uses the controller default."
            placeholder="e.g. 8.0.5"
            value={version}
            onChange={(e) => setVersion(e.currentTarget.value)}
          />
        )}
        {snort && (
          <>
            <PasswordInput
              label="Oinkcode"
              description="From your snort.org account. snort.org serves what your subscription allows: current rules for Snort Subscriber Rule Set subscribers, rules 30 days old for registered users."
              placeholder={hasOinkcode ? "Stored (leave empty to keep it)" : "40 hexadecimal characters"}
              value={oinkcode}
              disabled={clearOinkcode}
              onChange={(e) => setOinkcode(e.currentTarget.value)}
              error={oinkcodeError}
              autoComplete="off"
            />
            {hasOinkcode && (
              <Switch
                label="Remove the stored oinkcode"
                checked={clearOinkcode}
                onChange={(e) => setClearOinkcode(e.currentTarget.checked)}
              />
            )}
            <Select
              label="Ruleset"
              data={SNORT_RULESETS}
              value={ruleset}
              onChange={(v) => setRuleset(v ?? "auto")}
              allowDeselect={false}
            />
            <Select
              label="IPS policy"
              description="Talos policy whose rules are enabled; the others are written commented out (enable.conf can turn them on). Not used for the community ruleset."
              data={SNORT_POLICIES}
              value={policy}
              onChange={(v) => setPolicy(v ?? "balanced")}
              allowDeselect={false}
            />
            <Select
              label="Approximate conversions"
              description="Rules converted with a documented change in meaning (docs/snort2suricata.md)."
              data={SNORT_APPROX}
              value={approx}
              onChange={(v) => setApprox(v ?? "include")}
              allowDeselect={false}
            />
            <TextInput
              label="Snort version"
              description="Selects snortrules-snapshot-<version>; every Snort 3 snapshot has the same text rules, 2.x selects the Snort 2 rules. Empty uses the controller default."
              placeholder="e.g. 3.9.0.0"
              value={snortVersion}
              onChange={(e) => setSnortVersion(e.currentTarget.value)}
            />
          </>
        )}
        {provider.fetches && !snort && (
          <TextInput
            label="Download URL"
            description={
              provider.type === "et-open"
                ? "Optional: overrides the ET Open URL (e.g. a mirror). Empty uses the default."
                : "URL of a .rules file or a .tar.gz archive of rules."
            }
            placeholder="https://..."
            value={url}
            onChange={(e) => setUrl(e.currentTarget.value)}
          />
        )}
        {save.isError && <ErrorAlert error={save.error} title="Update failed" />}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending} disabled={(provider.fetches && seconds < 600) || !!oinkcodeError}>
            Save
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

function ProvidersPanel() {
  const qc = useQueryClient();
  const providers = useProviders();
  const [editing, setEditing] = useState<Provider | null>(null);
  const toggle = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) => api.rules.updateProvider({ name: v.name, enabled: v.enabled }),
    meta: { errorTitle: "Failed to update provider" },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["providers"] }),
  });
  const sync = useMutation({
    mutationFn: (name: string) => api.rules.syncProvider({ name }),
    meta: { errorTitle: "Sync failed" },
    onSuccess: (r, name) => {
      notifications.show({
        color: r.changed ? "green" : "blue",
        title: `Provider ${name}`,
        message: r.changed ? `New rules committed (${shortCommit(r.commit)})` : "Rules are up to date (no changes)",
      });
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ["providers"] });
      void qc.invalidateQueries({ queryKey: ["commits", Repo.RULES] });
      void qc.invalidateQueries({ queryKey: ["tree", Repo.RULES] });
      void qc.invalidateQueries({ queryKey: ["policies"] });
    },
  });
  if (providers.isPending) return <LoadingBlock />;
  if (providers.isError) return <ErrorAlert error={providers.error} onRetry={() => providers.refetch()} />;
  return (
    <>
      <ProviderEditModal provider={editing} onClose={() => setEditing(null)} />
      <Card withBorder padding={0}>
        {providers.data.length === 0 ? (
          <Empty>No rule providers configured.</Empty>
        ) : (
          <Table.ScrollContainer minWidth={1000}>
            <Table verticalSpacing="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Provider</Table.Th>
                  <Table.Th>Enabled</Table.Th>
                  <Table.Th>Interval</Table.Th>
                  <Table.Th>Options</Table.Th>
                  <Table.Th>Last fetch</Table.Th>
                  <Table.Th>Last success</Table.Th>
                  <Table.Th>Last commit</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {providers.data.map((p) => (
                  <Table.Tr key={p.name}>
                    <Table.Td>
                      <Group gap={6}>
                        <Text fw={600} ff="monospace">
                          {p.name}
                        </Text>
                        <Badge size="xs" variant="outline" color="gray">
                          {p.type}
                        </Badge>
                        {!p.fetches && (
                          <Badge size="xs" variant="light" color="teal">
                            editable
                          </Badge>
                        )}
                      </Group>
                      {p.lastError && (
                        <Tooltip label={p.lastError} multiline maw={480} withArrow>
                          <Text size="xs" c="red" lineClamp={1} maw={320}>
                            {p.lastError}
                          </Text>
                        </Tooltip>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Switch
                        checked={p.enabled}
                        disabled={toggle.isPending && toggle.variables?.name === p.name}
                        onChange={(e) => toggle.mutate({ name: p.name, enabled: e.currentTarget.checked })}
                      />
                    </Table.Td>
                    <Table.Td>{p.fetches ? formatDuration(p.intervalSeconds) : "-"}</Table.Td>
                    <Table.Td>
                      <Stack gap={0}>
                        {Object.entries(p.options).length === 0 ? (
                          <Text size="xs" c="dimmed">
                            {p.type === "et-open" ? "default version" : "-"}
                          </Text>
                        ) : (
                          Object.entries(p.options).map(([k, v]) => (
                            <Text size="xs" key={k} ff="monospace" lineClamp={1} maw={260}>
                              {k}={v}
                            </Text>
                          ))
                        )}
                      </Stack>
                    </Table.Td>
                    <Table.Td>{p.fetches ? <TimeAgo ts={p.lastFetchAt} /> : "-"}</Table.Td>
                    <Table.Td>{p.fetches ? <TimeAgo ts={p.lastSuccessAt} /> : "-"}</Table.Td>
                    <Table.Td>
                      <CommitId id={p.lastCommit} />
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4} wrap="nowrap" justify="flex-end">
                        {p.fetches && (
                          <Button
                            size="compact-xs"
                            variant="light"
                            leftSection={<IconRefresh size={12} />}
                            loading={sync.isPending && sync.variables === p.name}
                            onClick={() => sync.mutate(p.name)}
                          >
                            Sync now
                          </Button>
                        )}
                        <Tooltip label="Edit" withArrow>
                          <ActionIcon variant="subtle" onClick={() => setEditing(p)}>
                            <IconPencil size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>
      <Text size="xs" c="dimmed" mt="xs">
        Downloading rules (provider enabled) and deploying them to nodes (Deploy policy) are independent.
      </Text>
    </>
  );
}

// ---------------------------------------------------------------------------
// Local rule files
// ---------------------------------------------------------------------------

const RULE_FILE_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*\.(rules|config)$/;

function NewRuleFileModal(props: {
  opened: boolean;
  providers: string[];
  existing: Set<string>;
  onClose: () => void;
  onCreate: (path: string) => void;
}) {
  const [provider, setProvider] = useState<string | null>(props.providers[0] ?? null);
  const [name, setName] = useState("local.rules");
  const path = provider ? `${provider}/${name.trim()}` : "";
  const error = !name.trim()
    ? undefined
    : name.includes("..") || !RULE_FILE_RE.test(name.trim())
      ? "Use a name ending in .rules or .config (letters, digits, . _ - and /)"
      : props.existing.has(path)
        ? "This file already exists"
        : undefined;
  return (
    <Modal opened={props.opened} onClose={props.onClose} title="New rule file">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!error && provider && name.trim()) props.onCreate(path);
        }}
      >
        <Stack>
          <Select
            label="Provider"
            data={props.providers}
            value={provider}
            onChange={setProvider}
            allowDeselect={false}
          />
          <TextInput
            label="File name"
            value={name}
            onChange={(e) => setName(e.currentTarget.value)}
            error={error}
            description={path ? `Path: ${path}` : undefined}
            data-autofocus
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={props.onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!!error || !provider || !name.trim()}>
              Create
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function LocalRulesPanel() {
  const providers = useProviders();
  const tree = useTree(Repo.RULES);
  const [params, setParams] = useSearchParams();
  const selected = params.get("file") ?? "";
  const [newFiles, setNewFiles] = useState<string[]>([]);
  const [creating, setCreating] = useState(false);
  const { setDirty, guard } = useDirtyGuard();

  if (providers.isPending || tree.isPending) return <LoadingBlock />;
  if (providers.isError) return <ErrorAlert error={providers.error} />;
  if (tree.isError) return <ErrorAlert error={tree.error} onRetry={() => tree.refetch()} />;

  const editable = providers.data.filter((p) => !p.fetches).map((p) => p.name);
  const files = tree.data.entries.filter((e) => !e.dir);
  const existing = new Set(files.map((f) => f.path));
  const select = (path: string) =>
    guard(() => {
      const p = new URLSearchParams(params);
      if (path) p.set("file", path);
      else p.delete("file");
      setParams(p, { replace: true });
    });

  if (editable.length === 0) {
    return (
      <Alert color="blue">
        There is no editable rule provider. Rules of downloading providers (such as et-open) cannot be edited; add a{" "}
        <code>local</code> provider to the controller to manage your own rules.
      </Alert>
    );
  }

  const isNew = !!selected && !existing.has(selected);
  const selectedEditable = !!selected && editable.some((p) => selected.startsWith(p + "/"));

  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 3 }}>
        <Card withBorder padding="xs">
          <Group justify="space-between" mb="xs" px={4}>
            <Text fw={600} size="sm">
              Editable providers
            </Text>
            <Tooltip label="New rule file" withArrow>
              <ActionIcon variant="light" size="sm" onClick={() => setCreating(true)}>
                <IconPlus size={14} />
              </ActionIcon>
            </Tooltip>
          </Group>
          {editable.map((prov) => {
            const list = [
              ...files.filter((f) => f.path.startsWith(prov + "/")).map((f) => ({ path: f.path, size: f.size, unsaved: false })),
              ...newFiles
                .filter((p) => p.startsWith(prov + "/") && !existing.has(p))
                .map((p) => ({ path: p, size: 0n, unsaved: true })),
            ].sort((a, b) => a.path.localeCompare(b.path));
            return (
              <NavLink
                key={prov}
                label={prov + "/"}
                leftSection={<IconFolder size={16} />}
                defaultOpened
                childrenOffset={14}
              >
                {list.length === 0 && (
                  <Text size="xs" c="dimmed" px="sm" py={4}>
                    No files
                  </Text>
                )}
                {list.map((f) => (
                  <NavLink
                    key={f.path}
                    active={f.path === selected}
                    leftSection={<IconFile size={14} />}
                    label={f.path.slice(prov.length + 1)}
                    description={f.unsaved ? "new (unsaved)" : formatBytes(f.size)}
                    onClick={() => select(f.path)}
                  />
                ))}
              </NavLink>
            );
          })}
        </Card>
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 9 }}>
        {!selected ? (
          <Card withBorder>
            <Empty>Select a rule file or create a new one.</Empty>
          </Card>
        ) : !selectedEditable ? (
          <Alert color="yellow">"{selected}" does not belong to an editable provider.</Alert>
        ) : (
          <FileEditor
            key={selected + (isNew ? ":new" : "")}
            repo={Repo.RULES}
            path={selected}
            isNew={isNew}
            headCommit={tree.data.commit}
            initialContent={NEW_RULES_TEMPLATE}
            onDirtyChange={setDirty}
            onSaved={() => setNewFiles((l) => l.filter((p) => p !== selected))}
            onDeleted={() => {
              setDirty(false);
              select("");
            }}
            help="One rule per line. Lines starting with # are comments (disabled rules are recognized too)."
          />
        )}
      </Grid.Col>
      <NewRuleFileModal
        opened={creating}
        providers={editable}
        existing={existing}
        onClose={() => setCreating(false)}
        onCreate={(path) => {
          setCreating(false);
          setNewFiles((l) => [...new Set([...l, path])]);
          select(path);
        }}
      />
    </Grid>
  );
}

// ---------------------------------------------------------------------------

export default function RulesPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "providers";
  return (
    <>
      <PageHeader title="Rules" description="Rule providers, local rules and the rules repository history" />
      <Tabs
        value={tab}
        onChange={(v) => setParams(new URLSearchParams({ tab: v || "providers" }), { replace: true })}
        keepMounted={false}
      >
        <Tabs.List mb="md">
          <Tabs.Tab value="providers">Providers</Tabs.Tab>
          <Tabs.Tab value="local">Local rules</Tabs.Tab>
          <Tabs.Tab value="history">History</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="providers">
          <ProvidersPanel />
        </Tabs.Panel>
        <Tabs.Panel value="local">
          <LocalRulesPanel />
        </Tabs.Panel>
        <Tabs.Panel value="history">
          <CommitHistory repo={Repo.RULES} kind={DeployKind.RULES} />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
