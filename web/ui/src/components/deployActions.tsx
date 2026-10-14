import { Text } from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { DeployKind, DeployMode } from "../gen/suricontroller/api/v1/api_pb";
import { deployKindLabel, deployModeLabel } from "../lib/enums";
import { shortCommit } from "../lib/format";

export function useSetPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { kind: DeployKind; mode: DeployMode; pinnedCommit?: string }) =>
      api.deploy.setPolicy({ kind: v.kind, mode: v.mode, pinnedCommit: v.pinnedCommit ?? "" }),
    meta: { errorTitle: "Failed to change the deployment policy" },
    onSuccess: (r, v) => {
      const p = r.policy;
      notifications.show({
        color: "green",
        title: `${deployKindLabel(v.kind)} deployment: ${deployModeLabel(v.mode)}`,
        message: p?.effectiveCommit ? `Effective commit is now ${shortCommit(p.effectiveCommit)}` : "Policy updated",
      });
      void qc.invalidateQueries({ queryKey: ["policies"] });
      void qc.invalidateQueries({ queryKey: ["nodes"] });
      void qc.invalidateQueries({ queryKey: ["node"] });
    },
  });
}

/** "Deploy this commit" (pin) and "Resume auto" with confirmation dialogs. */
export function useDeployActions(kind: DeployKind) {
  const setPolicy = useSetPolicy();
  const label = deployKindLabel(kind).toLowerCase();
  const deployCommit = (commit: string, summary?: string) =>
    modals.openConfirmModal({
      title: `Deploy this ${label} commit`,
      children: (
        <Text size="sm">
          Pin the {label} deployment to <b>{shortCommit(commit)}</b>
          {summary ? ` (${summary})` : ""}? All nodes will receive this commit. New commits are not deployed until you
          resume automatic deployment.
        </Text>
      ),
      labels: { confirm: "Deploy", cancel: "Cancel" },
      onConfirm: () => setPolicy.mutate({ kind, mode: DeployMode.PINNED, pinnedCommit: commit }),
    });
  const resumeAuto = () =>
    modals.openConfirmModal({
      title: `Resume automatic ${label} deployment`,
      children: (
        <Text size="sm">
          Nodes will track the latest {label} commit again, starting with the current head.
        </Text>
      ),
      labels: { confirm: "Resume auto", cancel: "Cancel" },
      onConfirm: () => setPolicy.mutate({ kind, mode: DeployMode.AUTO }),
    });
  return { deployCommit, resumeAuto, setPolicy };
}
