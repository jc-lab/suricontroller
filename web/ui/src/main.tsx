import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MantineProvider, createTheme, localStorageColorSchemeManager } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { ModalsProvider } from "@mantine/modals";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "./global.css";
import { queryClient } from "./api/queryClient";
import { router } from "./router";

const theme = createTheme({
  primaryColor: "blue",
  defaultRadius: "sm",
  fontFamilyMonospace: "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace",
});

const colorSchemeManager = localStorageColorSchemeManager({ key: "mantine-color-scheme-value" });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto" colorSchemeManager={colorSchemeManager}>
      <QueryClientProvider client={queryClient}>
        <ModalsProvider labels={{ confirm: "Confirm", cancel: "Cancel" }}>
          <Notifications position="top-right" limit={5} />
          <RouterProvider router={router} />
        </ModalsProvider>
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);
