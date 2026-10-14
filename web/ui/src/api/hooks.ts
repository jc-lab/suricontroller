import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "./client";
import { authInfoKey } from "./queryClient";
import { Repo } from "../gen/suricontroller/api/v1/api_pb";

export const POLL_MS = 5_000;

export function useAuthInfo() {
  return useQuery({
    queryKey: authInfoKey,
    queryFn: () => api.auth.getAuthInfo({}),
    staleTime: 60_000,
  });
}

export function useNodes(poll = true) {
  return useQuery({
    queryKey: ["nodes"],
    queryFn: () => api.nodes.listNodes({}),
    select: (r) => r.nodes,
    refetchInterval: poll ? POLL_MS : false,
  });
}

export function useNode(id: string) {
  return useQuery({
    queryKey: ["node", id],
    queryFn: async () => (await api.nodes.getNode({ id })).node,
    refetchInterval: POLL_MS,
  });
}

export function usePolicies(poll = false) {
  return useQuery({
    queryKey: ["policies"],
    queryFn: () => api.deploy.getPolicies({}),
    refetchInterval: poll ? POLL_MS : false,
  });
}

export function useIngestStats(poll = true) {
  return useQuery({
    queryKey: ["ingestStats"],
    queryFn: () => api.logs.getIngestStats({}),
    refetchInterval: poll ? POLL_MS : false,
  });
}

export function useProviders() {
  return useQuery({
    queryKey: ["providers"],
    queryFn: async () => (await api.rules.listProviders({})).providers,
  });
}

export function useSystemInfo() {
  return useQuery({
    queryKey: ["systemInfo"],
    queryFn: () => api.system.getInfo({}),
    staleTime: 60_000,
  });
}

/** A single page of commits (e.g. for commit pickers). */
export function useCommits(repo: Repo, limit = 100, enabled = true) {
  return useQuery({
    queryKey: ["commits", repo, "list", limit],
    queryFn: () => api.repo.listCommits({ repo, limit }),
    enabled,
  });
}

export const COMMIT_PAGE = 30;

/** Paginated commit history (uses `before`). */
export function useCommitHistory(repo: Repo, path = "") {
  return useInfiniteQuery({
    queryKey: ["commits", repo, "history", path],
    queryFn: ({ pageParam }) => api.repo.listCommits({ repo, limit: COMMIT_PAGE, before: pageParam, path }),
    initialPageParam: "",
    getNextPageParam: (last) =>
      last.commits.length < COMMIT_PAGE ? undefined : last.commits[last.commits.length - 1]?.id,
  });
}

export function useTree(repo: Repo, path = "", recursive = true) {
  return useQuery({
    queryKey: ["tree", repo, path, recursive],
    queryFn: () => api.repo.listTree({ repo, path, recursive }),
  });
}

export function useCollectionPolicies() {
  return useQuery({
    queryKey: ["collectionPolicies"],
    queryFn: () => api.logs.getCollectionPolicies({}),
  });
}

export { Repo };
