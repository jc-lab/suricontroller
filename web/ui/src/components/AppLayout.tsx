import { Suspense } from "react";
import {
  ActionIcon,
  AppShell,
  Burger,
  Group,
  Menu,
  NavLink,
  ScrollArea,
  Text,
  Tooltip,
  UnstyledButton,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconChevronDown,
  IconDeviceDesktop,
  IconFileCode,
  IconGauge,
  IconLogout,
  IconMoon,
  IconRocket,
  IconServer2,
  IconSettings,
  IconShieldCheck,
  IconSun,
  IconTerminal2,
  IconUser,
} from "@tabler/icons-react";
import { Link, Outlet, useLocation, useNavigate } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuthInfo } from "../api/hooks";
import { authInfoKey, queryClient } from "../api/queryClient";
import { LoadingBlock } from "./common";

const NAV = [
  { to: "/", label: "Dashboard", icon: IconGauge, exact: true },
  { to: "/nodes", label: "Nodes", icon: IconServer2 },
  { to: "/rules", label: "Rules", icon: IconShieldCheck },
  { to: "/config", label: "Config", icon: IconFileCode },
  { to: "/deploy", label: "Deploy", icon: IconRocket },
  { to: "/logs", label: "Logs", icon: IconTerminal2 },
  { to: "/system", label: "System", icon: IconSettings },
];

function ColorSchemeToggle() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const next = colorScheme === "auto" ? "light" : colorScheme === "light" ? "dark" : "auto";
  const Icon = colorScheme === "auto" ? IconDeviceDesktop : colorScheme === "light" ? IconSun : IconMoon;
  return (
    <Tooltip label={`Theme: ${colorScheme} (click for ${next})`} withArrow>
      <ActionIcon variant="default" size="lg" onClick={() => setColorScheme(next)} aria-label="Toggle color scheme">
        <Icon size={18} />
      </ActionIcon>
    </Tooltip>
  );
}

function UserMenu() {
  const auth = useAuthInfo();
  const navigate = useNavigate();
  const p = auth.data?.principal;
  const logout = useMutation({
    mutationFn: () => api.auth.logout({}),
    meta: { errorTitle: "Logout failed" },
    onSuccess: () => {
      queryClient.clear();
      void queryClient.invalidateQueries({ queryKey: authInfoKey });
      navigate("/login", { replace: true });
    },
  });
  return (
    <Menu position="bottom-end" withArrow>
      <Menu.Target>
        <UnstyledButton>
          <Group gap={6}>
            <IconUser size={18} />
            <Text size="sm" fw={500} visibleFrom="xs">
              {p?.displayName || p?.id}
            </Text>
            <IconChevronDown size={14} />
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Signed in as {p?.displayName || p?.id}</Menu.Label>
        {p?.roles && p.roles.length > 0 && <Menu.Label>Roles: {p.roles.join(", ")}</Menu.Label>}
        <Menu.Item leftSection={<IconLogout size={16} />} onClick={() => logout.mutate()}>
          Log out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure();
  const location = useLocation();
  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 210, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Link to="/" style={{ textDecoration: "none", color: "inherit" }}>
              <Group gap={8} wrap="nowrap">
                <IconShieldCheck size={24} color="var(--mantine-primary-color-filled)" />
                <Text fw={700} size="lg">
                  suricontroller
                </Text>
              </Group>
            </Link>
          </Group>
          <Group gap="sm" wrap="nowrap">
            <ColorSchemeToggle />
            <UserMenu />
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="xs">
        <AppShell.Section grow component={ScrollArea}>
          {NAV.map((item) => {
            const active = item.exact
              ? location.pathname === item.to
              : location.pathname === item.to || location.pathname.startsWith(item.to + "/");
            return (
              <NavLink
                key={item.to}
                component={Link}
                to={item.to}
                label={item.label}
                leftSection={<item.icon size={18} stroke={1.6} />}
                active={active}
                onClick={close}
                style={{ borderRadius: "var(--mantine-radius-sm)" }}
              />
            );
          })}
        </AppShell.Section>
      </AppShell.Navbar>
      <AppShell.Main>
        <Suspense fallback={<LoadingBlock h={300} />}>
          <Outlet />
        </Suspense>
      </AppShell.Main>
    </AppShell>
  );
}
