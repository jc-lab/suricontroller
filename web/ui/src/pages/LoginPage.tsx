import { useState } from "react";
import { Alert, Anchor, Button, Center, Paper, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconAlertTriangle, IconShieldCheck } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { Navigate, useLocation, useNavigate } from "react-router";
import { api } from "../api/client";
import { useAuthInfo } from "../api/hooks";
import { authInfoKey, queryClient } from "../api/queryClient";
import { Code, errorMessage, isCode } from "../api/errors";
import { ErrorAlert, LoadingBlock } from "../components/common";

export function LoginPage() {
  const auth = useAuthInfo();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from || "/";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const login = useMutation({
    mutationFn: async () => {
      await api.auth.login({ username, password });
      // Verify that the session cookie is stored and sent back.
      const info = await api.auth.getAuthInfo({});
      if (!info.principal) {
        throw new Error(
          "Signed in, but the browser did not keep the session cookie. When the controller is served over plain " +
            "HTTP, enable insecure_cookie (SURICONTROLLER_INSECURE_COOKIE=1) or use HTTPS.",
        );
      }
      return info;
    },
    meta: { silent: true },
    onSuccess: (info) => {
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== authInfoKey[0] });
      queryClient.setQueryData(authInfoKey, info);
      navigate(from === "/login" ? "/" : from, { replace: true });
    },
  });

  if (auth.isPending) return <LoadingBlock h="100vh" />;
  if (auth.data?.principal) return <Navigate to={from === "/login" ? "/" : from} replace />;

  const passwordLogin = auth.data?.passwordLogin ?? true;
  const loginUrl = auth.data?.loginUrl;

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder shadow="sm" p="xl" radius="md" w={380}>
        <Stack>
          <Stack gap={4} align="center">
            <IconShieldCheck size={40} color="var(--mantine-primary-color-filled)" />
            <Title order={3}>suricontroller</Title>
            <Text c="dimmed" size="sm">
              Sign in to manage your Suricata nodes
            </Text>
          </Stack>
          {auth.isError && <ErrorAlert error={auth.error} title="Cannot reach the controller" />}
          {passwordLogin ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                login.mutate();
              }}
            >
              <Stack>
                {login.isError && (
                  <Alert color="red" icon={<IconAlertTriangle size={18} />}>
                    {isCode(login.error, Code.Unauthenticated)
                      ? "Invalid username or password."
                      : errorMessage(login.error)}
                  </Alert>
                )}
                <TextInput
                  label="Username"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.currentTarget.value)}
                  required
                  autoFocus
                />
                <PasswordInput
                  label="Password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.currentTarget.value)}
                  required
                />
                <Button type="submit" loading={login.isPending} fullWidth>
                  Sign in
                </Button>
              </Stack>
            </form>
          ) : loginUrl ? (
            <Button component="a" href={loginUrl} fullWidth>
              Continue to sign in
            </Button>
          ) : (
            <Alert color="yellow">Password login is not available and no login URL is configured.</Alert>
          )}
          {passwordLogin && loginUrl && (
            <Text size="sm" ta="center">
              or <Anchor href={loginUrl}>sign in with an external provider</Anchor>
            </Text>
          )}
        </Stack>
      </Paper>
    </Center>
  );
}
