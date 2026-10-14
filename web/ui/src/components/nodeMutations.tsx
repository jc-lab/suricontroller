import { useMutation, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { modals } from "@mantine/modals";
import { Text } from "@mantine/core";
import { api } from "../api/client";

export function useToggleNode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { id: string; enabled: boolean }) => api.nodes.updateNode({ id: v.id, enabled: v.enabled }),
    meta: { errorTitle: "Failed to update node" },
    onSuccess: (r) => {
      notifications.show({ color: "green", message: `Node ${r.node?.id} ${r.node?.enabled ? "enabled" : "disabled"}` });
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      void qc.invalidateQueries({ queryKey: ["node", r.node?.id] });
    },
  });
}

export function useDeleteNode(onDeleted?: () => void) {
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: (id: string) => api.nodes.deleteNode({ id }),
    meta: { errorTitle: "Failed to delete node" },
    onSuccess: (_r, id) => {
      notifications.show({ color: "green", message: `Node ${id} deleted` });
      qc.removeQueries({ queryKey: ["node", id] });
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      onDeleted?.();
    },
  });
  const confirm = (id: string) =>
    modals.openConfirmModal({
      title: "Delete node",
      children: (
        <Text size="sm">
          Delete node <b>{id}</b>? Its key is removed and the agent is disconnected. Stored logs and config files in{" "}
          <code>nodes/{id}/</code> are not deleted.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => m.mutate(id),
    });
  return { ...m, confirm };
}
