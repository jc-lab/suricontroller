import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { Code, errorMessage, isCode } from "./errors";
import type { GetAuthInfoResponse } from "../gen/suricontroller/api/v1/api_pb";

declare module "@tanstack/react-query" {
  interface Register {
    mutationMeta: {
      /** Do not show the global error notification (handled by the caller). */
      silent?: boolean;
      /** Title of the error notification. */
      errorTitle?: string;
    };
  }
}

export const authInfoKey = ["authInfo"] as const;

/** Marks the session as logged out; RequireAuth then redirects to login. */
export function markLoggedOut(): void {
  const old = queryClient.getQueryData<GetAuthInfoResponse>(authInfoKey);
  if (old?.principal) {
    queryClient.setQueryData<GetAuthInfoResponse>(authInfoKey, { ...old, principal: undefined });
  } else if (!old) {
    void queryClient.invalidateQueries({ queryKey: authInfoKey });
  }
}

const noRetryCodes = [
  Code.Unauthenticated,
  Code.PermissionDenied,
  Code.InvalidArgument,
  Code.NotFound,
  Code.FailedPrecondition,
  Code.Unimplemented,
];

export const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (err) => {
      if (isCode(err, Code.Unauthenticated)) markLoggedOut();
    },
  }),
  mutationCache: new MutationCache({
    onError: (err, _vars, _ctx, mutation) => {
      if (isCode(err, Code.Unauthenticated)) {
        markLoggedOut();
        return;
      }
      if (mutation.meta?.silent) return;
      notifications.show({
        color: "red",
        title: mutation.meta?.errorTitle ?? "Request failed",
        message: errorMessage(err),
        autoClose: 8000,
      });
    },
  }),
  defaultOptions: {
    queries: {
      retry: (count, err) => !noRetryCodes.some((c) => isCode(err, c)) && count < 2,
      staleTime: 2_000,
      refetchOnWindowFocus: true,
    },
  },
});
