import { Button, Center, Stack, Text, Title } from "@mantine/core";
import { useRouteError } from "react-router";

export function RouteError() {
  const err = useRouteError();
  const msg = err instanceof Error ? err.message : String(err);
  const chunkError = /dynamically imported module|Failed to fetch|Importing a module script failed/i.test(msg);
  return (
    <Center h="80vh" p="md">
      <Stack align="center" maw={560}>
        <Title order={3}>Something went wrong</Title>
        <Text c="dimmed" ta="center" style={{ wordBreak: "break-word" }}>
          {chunkError ? "The UI was updated or the controller is unreachable. Reload the page." : msg}
        </Text>
        <Button onClick={() => window.location.reload()}>Reload</Button>
      </Stack>
    </Center>
  );
}
