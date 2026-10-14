import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import {
  AuthService,
  DeployService,
  LogService,
  NodeService,
  RepoService,
  RuleService,
  SystemService,
} from "../gen/suricontroller/api/v1/api_pb";

/**
 * Resolves the API base URL. The Go handler may inject
 * <meta name="suricontroller-api" content="...">; otherwise the API is at
 * "./api" relative to the page, which works under any path prefix.
 */
export function resolveApiBase(): string {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="suricontroller-api"]');
  const raw = meta?.content?.trim() || "api";
  const url = new URL(raw, document.baseURI);
  url.hash = "";
  url.search = "";
  return url.href.replace(/\/+$/, "");
}

export const apiBase = resolveApiBase();

export const transport = createConnectTransport({
  baseUrl: apiBase,
  useBinaryFormat: false,
  fetch: (input, init) => globalThis.fetch(input, { ...init, credentials: "same-origin" }),
});

export const api = {
  auth: createClient(AuthService, transport),
  system: createClient(SystemService, transport),
  nodes: createClient(NodeService, transport),
  repo: createClient(RepoService, transport),
  rules: createClient(RuleService, transport),
  deploy: createClient(DeployService, transport),
  logs: createClient(LogService, transport),
};

/** URL of a stored log segment (plain GET, cookie auth). */
export function logDownloadUrl(nodeId: string, path: string): string {
  const q = new URLSearchParams({ node: nodeId, path });
  return `${apiBase}/logs/download?${q.toString()}`;
}
