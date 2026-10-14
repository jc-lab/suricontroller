import { Badge, Tooltip } from "@mantine/core";
import type { Node, DeployPolicy } from "../gen/suricontroller/api/v1/api_pb";
import { ApplyStatus } from "../gen/suricontroller/agent/v1/agent_pb";
import { applyStatusColor, applyStatusLabel, deployModeColor, deployModeLabel } from "../lib/enums";

export function OnlineBadge({ node }: { node: Node }) {
  if (!node.enabled) {
    return (
      <Badge color="gray" variant="outline" size="sm">
        Disabled
      </Badge>
    );
  }
  return node.online ? (
    <Badge color="green" variant="dot" size="sm">
      Online
    </Badge>
  ) : (
    <Badge color="gray" variant="dot" size="sm">
      Offline
    </Badge>
  );
}

export type SyncState = "error" | "failed" | "synced" | "pending" | "none";

export function nodeSyncState(node: Node): SyncState {
  const d = node.deploy;
  if (!d) return "none";
  if (d.desiredError) return "error";
  if (d.lastStatus === ApplyStatus.FAILED || d.lastStatus === ApplyStatus.ROLLED_BACK) {
    if (!d.inSync) return "failed";
  }
  if (d.inSync) return "synced";
  if (d.desiredGeneration === 0n) return "none";
  return "pending";
}

export function nodeHasProblem(node: Node): boolean {
  const d = node.deploy;
  if (!d) return false;
  return (
    !!d.desiredError ||
    d.lastStatus === ApplyStatus.FAILED ||
    d.lastStatus === ApplyStatus.ROLLED_BACK
  );
}

export function SyncBadge({ node }: { node: Node }) {
  const s = nodeSyncState(node);
  const d = node.deploy;
  switch (s) {
    case "error":
      return (
        <Tooltip label={d?.desiredError} multiline maw={420} withArrow>
          <Badge color="red" size="sm">
            Render error
          </Badge>
        </Tooltip>
      );
    case "failed":
      return (
        <Tooltip label={d?.lastMessage || applyStatusLabel(d!.lastStatus)} multiline maw={420} withArrow>
          <Badge color={applyStatusColor(d!.lastStatus)} size="sm">
            {applyStatusLabel(d!.lastStatus)}
          </Badge>
        </Tooltip>
      );
    case "synced":
      return (
        <Badge color="green" variant="light" size="sm">
          In sync
        </Badge>
      );
    case "pending":
      return (
        <Badge color="yellow" variant="light" size="sm">
          {d?.lastStatus === ApplyStatus.IN_PROGRESS ? "Applying" : "Out of sync"}
        </Badge>
      );
    default:
      return (
        <Badge color="gray" variant="light" size="sm">
          No state
        </Badge>
      );
  }
}

export function ApplyStatusBadge({ status }: { status: ApplyStatus }) {
  return (
    <Badge color={applyStatusColor(status)} variant="light" size="sm">
      {applyStatusLabel(status)}
    </Badge>
  );
}

export function DeployModeBadge({ policy }: { policy?: DeployPolicy }) {
  if (!policy) return null;
  return (
    <Badge color={deployModeColor(policy.mode)} variant="light" size="sm">
      {deployModeLabel(policy.mode)}
    </Badge>
  );
}
