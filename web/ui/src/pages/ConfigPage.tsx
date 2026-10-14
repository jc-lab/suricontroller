import { useEffect, useState, type ReactNode } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Grid,
  Group,
  Menu,
  NavLink,
  ScrollArea,
  Tabs,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { IconEye, IconFile, IconFolder, IconPlus, IconSearch, IconServer2 } from "@tabler/icons-react";
import { useSearchParams } from "react-router";
import { Repo, useNodes, useTree } from "../api/hooks";
import { DeployKind } from "../gen/suricontroller/api/v1/api_pb";
import { CommitHistory } from "../components/CommitHistory";
import { FileEditor } from "../components/FileEditor";
import { Empty, ErrorAlert, LoadingBlock, PageHeader } from "../components/common";
import { CONFIG_FILES, CONFIG_FILE_HELP } from "../lib/enums";
import { formatBytes } from "../lib/format";
import { useDirtyGuard } from "../lib/useDirtyGuard";
import { CONFIG_TEMPLATES } from "../lib/templates";
import { PreviewModal } from "./node/PreviewModal";

function fileOrder(a: string, b: string): number {
  const ia = CONFIG_FILES.indexOf(a.split("/").pop() ?? "");
  const ib = CONFIG_FILES.indexOf(b.split("/").pop() ?? "");
  return ia - ib || a.localeCompare(b);
}

function DirEntry(props: {
  dir: string;
  label: string;
  icon: ReactNode;
  description?: string;
  files: { path: string; size: bigint; unsaved?: boolean }[];
  selected: string;
  defaultOpened?: boolean;
  onSelect: (path: string) => void;
}) {
  const present = new Set(props.files.map((f) => f.path.slice(props.dir.length + 1)));
  const missing = CONFIG_FILES.filter((f) => !present.has(f));
  const containsSelected = props.selected.startsWith(props.dir + "/");
  const [opened, setOpened] = useState(!!props.defaultOpened || containsSelected);
  useEffect(() => {
    if (containsSelected) setOpened(true);
  }, [containsSelected]);
  return (
    <NavLink
      opened={opened}
      onChange={setOpened}
      label={
        <Group gap={4} wrap="nowrap" justify="space-between">
          <Text size="sm" truncate>
            {props.label}
          </Text>
          {props.files.length > 0 && (
            <Badge size="xs" variant="light" color="gray">
              {props.files.length}
            </Badge>
          )}
        </Group>
      }
      description={props.description}
      leftSection={props.icon}
      childrenOffset={14}
    >
      {props.files.map((f) => (
        <NavLink
          key={f.path}
          active={f.path === props.selected}
          leftSection={<IconFile size={14} />}
          label={f.path.slice(props.dir.length + 1)}
          description={f.unsaved ? "new (unsaved)" : formatBytes(f.size)}
          onClick={() => props.onSelect(f.path)}
        />
      ))}
      {missing.length > 0 && (
        <Menu position="right-start" withArrow>
          <Menu.Target>
            <NavLink
              leftSection={<IconPlus size={14} />}
              label={<Text size="xs" c="dimmed">New file...</Text>}
            />
          </Menu.Target>
          <Menu.Dropdown>
            <Menu.Label>Create in {props.dir}/</Menu.Label>
            {missing.map((f) => (
              <Menu.Item key={f} onClick={() => props.onSelect(`${props.dir}/${f}`)}>
                <Text size="sm" ff="monospace">
                  {f}
                </Text>
                <Text size="xs" c="dimmed">
                  {CONFIG_FILE_HELP[f]}
                </Text>
              </Menu.Item>
            ))}
          </Menu.Dropdown>
        </Menu>
      )}
    </NavLink>
  );
}

function FilesPanel() {
  const tree = useTree(Repo.CONFIG);
  const nodes = useNodes(false);
  const [params, setParams] = useSearchParams();
  const selected = params.get("file") ?? "";
  const [filter, setFilter] = useState("");
  const [preview, setPreview] = useState<string | null>(null);
  const { setDirty, guard } = useDirtyGuard();

  if (tree.isPending || nodes.isPending) return <LoadingBlock />;
  if (tree.isError) return <ErrorAlert error={tree.error} onRetry={() => tree.refetch()} />;
  if (nodes.isError) return <ErrorAlert error={nodes.error} onRetry={() => nodes.refetch()} />;

  const files = tree.data.entries.filter((e) => !e.dir);
  const existing = new Set(files.map((f) => f.path));
  const filesIn = (dir: string) => {
    const list: { path: string; size: bigint; unsaved?: boolean }[] = files
      .filter((f) => f.path.startsWith(dir + "/") && !f.path.slice(dir.length + 1).includes("/"))
      .map((f) => ({ path: f.path, size: f.size }));
    if (selected.startsWith(dir + "/") && !existing.has(selected) && !selected.slice(dir.length + 1).includes("/")) {
      list.push({ path: selected, size: 0n, unsaved: true });
    }
    return list.sort((a, b) => fileOrder(a.path, b.path));
  };

  // Node directories: registered nodes plus directories left in the repository.
  const known = new Map(nodes.data.map((n) => [n.id, n]));
  const dirIds = new Set<string>(nodes.data.map((n) => n.id));
  files.forEach((f) => {
    const m = /^nodes\/([^/]+)\//.exec(f.path);
    if (m) dirIds.add(m[1]!);
  });
  const nodeIds = [...dirIds].sort().filter((id) => !filter || id.toLowerCase().includes(filter.toLowerCase()));

  const select = (path: string) =>
    guard(() => {
      const p = new URLSearchParams(params);
      if (path) p.set("file", path);
      else p.delete("file");
      setParams(p, { replace: true });
    });

  const fileName = selected.split("/").pop() ?? "";
  const validSelection = /^(common\/[^/]+|nodes\/[^/]+\/[^/]+)$/.test(selected) && CONFIG_FILES.includes(fileName);
  const isNew = validSelection && !existing.has(selected);
  const nodeOfSelected = /^nodes\/([^/]+)\//.exec(selected)?.[1];

  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 3 }}>
        <Card withBorder padding="xs">
          <DirEntry
            dir="common"
            label="common/"
            description="Shared by all nodes"
            icon={<IconFolder size={16} />}
            files={filesIn("common")}
            selected={selected}
            defaultOpened
            onSelect={select}
          />
          <Text size="xs" fw={600} c="dimmed" tt="uppercase" mt="sm" mb={4} px={8}>
            nodes/
          </Text>
          {dirIds.size > 8 && (
            <TextInput
              size="xs"
              mb={4}
              placeholder="Filter nodes"
              leftSection={<IconSearch size={12} />}
              value={filter}
              onChange={(e) => setFilter(e.currentTarget.value)}
            />
          )}
          <ScrollArea.Autosize mah="calc(100vh - 360px)">
            {nodeIds.length === 0 && (
              <Text size="xs" c="dimmed" px={8}>
                No nodes registered.
              </Text>
            )}
            {nodeIds.map((id) => {
              const dir = `nodes/${id}`;
              return (
                <DirEntry
                  key={id}
                  dir={dir}
                  label={id}
                  description={known.has(id) ? known.get(id)?.description || undefined : "unknown node"}
                  icon={<IconServer2 size={16} />}
                  files={filesIn(dir)}
                  selected={selected}
                  onSelect={select}
                />
              );
            })}
          </ScrollArea.Autosize>
        </Card>
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 9 }}>
        {!selected ? (
          <Card withBorder>
            <Empty>
              Select a file, or use "New file..." under <code>common/</code> or a node to create one. Allowed files:{" "}
              {CONFIG_FILES.join(", ")}.
            </Empty>
          </Card>
        ) : !validSelection ? (
          <Alert color="yellow">
            "{selected}" is not an allowed configuration file. Use <code>common/&lt;file&gt;</code> or{" "}
            <code>nodes/&lt;node-id&gt;/&lt;file&gt;</code> with one of: {CONFIG_FILES.join(", ")}.
          </Alert>
        ) : (
          <FileEditor
            key={selected + (isNew ? ":new" : "")}
            repo={Repo.CONFIG}
            path={selected}
            isNew={isNew}
            headCommit={tree.data.commit}
            initialContent={CONFIG_TEMPLATES[fileName] ?? ""}
            onDirtyChange={setDirty}
            onDeleted={() => {
              setDirty(false);
              select("");
            }}
            help={CONFIG_FILE_HELP[fileName]}
            toolbar={
              nodeOfSelected && known.has(nodeOfSelected) ? (
                <Tooltip label={`Render the bundle for ${nodeOfSelected}`} withArrow>
                  <Button size="xs" variant="light" leftSection={<IconEye size={14} />} onClick={() => setPreview(nodeOfSelected)}>
                    Preview
                  </Button>
                </Tooltip>
              ) : undefined
            }
          />
        )}
      </Grid.Col>
      {preview && <PreviewModal nodeId={preview} opened onClose={() => setPreview(null)} />}
    </Grid>
  );
}

export default function ConfigPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "files";
  return (
    <>
      <PageHeader
        title="Config"
        description="Suricata configuration repository: common/ for all nodes, nodes/<id>/ for per-node overrides"
      />
      <Tabs
        value={tab}
        onChange={(v) => {
          const p = new URLSearchParams(params);
          p.set("tab", v || "files");
          setParams(p, { replace: true });
        }}
        keepMounted={false}
      >
        <Tabs.List mb="md">
          <Tabs.Tab value="files">Files</Tabs.Tab>
          <Tabs.Tab value="history">History</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="files">
          <FilesPanel />
        </Tabs.Panel>
        <Tabs.Panel value="history">
          <CommitHistory repo={Repo.CONFIG} kind={DeployKind.CONFIG} />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
