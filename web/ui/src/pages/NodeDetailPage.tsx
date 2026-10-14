import { useState } from "react";
import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Breadcrumbs,
  Button,
  Group,
  Modal,
  Stack,
  Switch,
  Tabs,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconAlertTriangle, IconEye, IconPencil, IconTrash } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { api } from "../api/client";
import { useNode } from "../api/hooks";
import { Code, isCode } from "../api/errors";
import { ErrorAlert, LoadingBlock } from "../components/common";
import { OnlineBadge, SyncBadge } from "../components/badges";
import { useDeleteNode, useToggleNode } from "../components/nodeMutations";
import { OverviewPanel } from "./node/OverviewPanel";
import { InterfacesPanel } from "./node/InterfacesPanel";
import { InstancesPanel } from "./node/InstancesPanel";
import { DeployPanel } from "./node/DeployPanel";
import { NodeLogsPanel } from "./node/NodeLogsPanel";
import { NodeConfigPanel } from "./node/NodeConfigPanel";
import { PreviewModal } from "./node/PreviewModal";

function EditDescription({ id, value }: { id: string; value: string }) {
  const qc = useQueryClient();
  const [opened, setOpened] = useState(false);
  const [desc, setDesc] = useState(value);
  const save = useMutation({
    mutationFn: () => api.nodes.updateNode({ id, description: desc.trim() }),
    meta: { errorTitle: "Failed to update description" },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["node", id] });
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      setOpened(false);
    },
  });
  return (
    <>
      <Tooltip label="Edit description" withArrow>
        <ActionIcon
          variant="subtle"
          size="sm"
          onClick={() => {
            setDesc(value);
            setOpened(true);
          }}
        >
          <IconPencil size={14} />
        </ActionIcon>
      </Tooltip>
      <Modal opened={opened} onClose={() => setOpened(false)} title="Edit description">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Stack>
            <TextInput value={desc} onChange={(e) => setDesc(e.currentTarget.value)} data-autofocus />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setOpened(false)}>
                Cancel
              </Button>
              <Button type="submit" loading={save.isPending}>
                Save
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </>
  );
}

export default function NodeDetailPage() {
  const id = useParams().id ?? "";
  const node = useNode(id);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "overview";
  const [preview, setPreview] = useState(false);
  const toggle = useToggleNode();
  const del = useDeleteNode(() => navigate("/nodes"));

  const crumbs = (
    <Breadcrumbs mb="xs">
      <Anchor component={Link} to="/nodes" size="sm">
        Nodes
      </Anchor>
      <Text size="sm">{id}</Text>
    </Breadcrumbs>
  );

  if (node.isPending) return <LoadingBlock />;
  if (node.isError || !node.data) {
    return (
      <>
        {crumbs}
        {isCode(node.error, Code.NotFound) ? (
          <Alert color="yellow" icon={<IconAlertTriangle size={18} />} title="Node not found">
            The node "{id}" does not exist. <Anchor component={Link} to="/nodes">Back to nodes</Anchor>
          </Alert>
        ) : (
          <ErrorAlert error={node.error} onRetry={() => node.refetch()} />
        )}
      </>
    );
  }
  const n = node.data;

  return (
    <>
      {crumbs}
      <Group justify="space-between" align="flex-start" mb="md" wrap="wrap">
        <div>
          <Group gap="sm">
            <Title order={2}>{n.id}</Title>
            <OnlineBadge node={n} />
            <SyncBadge node={n} />
            {n.warnings.length > 0 && (
              <Badge color="yellow" variant="light" size="sm">
                {n.warnings.length} warning{n.warnings.length > 1 ? "s" : ""}
              </Badge>
            )}
          </Group>
          <Group gap={4} mt={4}>
            <Text c="dimmed" size="sm">
              {n.description || "No description"}
            </Text>
            <EditDescription id={n.id} value={n.description} />
          </Group>
        </div>
        <Group gap="sm">
          <Switch
            label="Enabled"
            checked={n.enabled}
            disabled={toggle.isPending}
            onChange={(e) => toggle.mutate({ id: n.id, enabled: e.currentTarget.checked })}
          />
          <Button variant="light" leftSection={<IconEye size={16} />} onClick={() => setPreview(true)}>
            Preview
          </Button>
          <Button variant="light" color="red" leftSection={<IconTrash size={16} />} onClick={() => del.confirm(n.id)}>
            Delete
          </Button>
        </Group>
      </Group>
      {!n.enabled && (
        <Alert color="gray" mb="md">
          This node is disabled: the agent's connections are rejected.
        </Alert>
      )}
      <PreviewModal nodeId={n.id} opened={preview} onClose={() => setPreview(false)} />
      <Tabs
        value={tab}
        onChange={(v) => {
          const p = new URLSearchParams(params);
          p.set("tab", v || "overview");
          setParams(p, { replace: true });
        }}
        keepMounted={false}
      >
        <Tabs.List mb="md">
          <Tabs.Tab value="overview">Overview</Tabs.Tab>
          <Tabs.Tab value="interfaces">Interfaces ({n.interfaces.length})</Tabs.Tab>
          <Tabs.Tab value="instances">Instances ({n.instances.length})</Tabs.Tab>
          <Tabs.Tab value="deploy">Deploy &amp; history</Tabs.Tab>
          <Tabs.Tab value="logs">Logs</Tabs.Tab>
          <Tabs.Tab value="config">Config files</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="overview">
          <OverviewPanel node={n} />
        </Tabs.Panel>
        <Tabs.Panel value="interfaces">
          <InterfacesPanel node={n} />
        </Tabs.Panel>
        <Tabs.Panel value="instances">
          <InstancesPanel node={n} />
        </Tabs.Panel>
        <Tabs.Panel value="deploy">
          <DeployPanel node={n} onPreview={() => setPreview(true)} />
        </Tabs.Panel>
        <Tabs.Panel value="logs">
          <NodeLogsPanel node={n} />
        </Tabs.Panel>
        <Tabs.Panel value="config">
          <NodeConfigPanel node={n} onPreview={() => setPreview(true)} />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
