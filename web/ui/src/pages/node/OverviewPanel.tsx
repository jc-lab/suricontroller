import { Alert, Badge, Card, Group, Progress, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import type { Node } from "../../gen/suricontroller/api/v1/api_pb";
import { CopyText, InfoGrid, TimeAgo, YesNo } from "../../components/common";
import { formatBytes, formatNumber, toNumber } from "../../lib/format";

export function OverviewPanel({ node: n }: { node: Node }) {
  const p = n.platform;
  const e = n.engine;
  const q = n.logQueue;
  const qCap = toNumber(q?.capacityBytes);
  const qPct = qCap > 0 ? (toNumber(q?.bytes) / qCap) * 100 : 0;
  return (
    <Stack>
      {n.warnings.length > 0 && (
        <Alert color="yellow" icon={<IconAlertTriangle size={18} />} title="Warnings reported by the agent">
          <Stack gap={4}>
            {n.warnings.map((w, i) => (
              <Text size="sm" key={i}>
                <Badge size="xs" variant="outline" color="yellow" mr={6}>
                  {w.code || "warning"}
                </Badge>
                {w.message}
              </Text>
            ))}
          </Stack>
        </Alert>
      )}
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Title order={5} mb="sm">
            Connection
          </Title>
          <InfoGrid
            items={[
              ["Status", n.online ? "Connected" : "Disconnected"],
              ["Remote address", n.remoteAddr || "-"],
              ["Connected", n.online ? <TimeAgo ts={n.connectedAt} /> : "-"],
              ["Last seen", n.online ? "now" : <TimeAgo ts={n.lastSeenAt} />],
              ["Registered", <TimeAgo ts={n.createdAt} />],
              ["Agent version", n.agentVersion || "-"],
            ]}
          />
        </Card>
        <Card withBorder>
          <Title order={5} mb="sm">
            Platform
          </Title>
          {p ? (
            <InfoGrid
              items={[
                ["Profile", p.profile || "-"],
                ["Hostname", p.hostname || "-"],
                ["OS", [p.osName, p.osVersion].filter(Boolean).join(" ") || "-"],
                ["Architecture", p.arch || "-"],
                ["Kernel", p.kernel || "-"],
                ["Firewall backend", p.firewallBackend || "-"],
              ]}
            />
          ) : (
            <Text size="sm" c="dimmed">
              The node has not connected yet.
            </Text>
          )}
        </Card>
        <Card withBorder>
          <Title order={5} mb="sm">
            Suricata engine
          </Title>
          {e ? (
            <InfoGrid
              items={[
                ["Version", e.version || "-"],
                ["NFQUEUE (IPS)", <YesNo value={e.nfq} yes="supported" no="not supported" />],
                ["AF_PACKET (IDS)", <YesNo value={e.afPacket} yes="supported" no="not supported" />],
                [
                  "Features",
                  e.features.length ? (
                    <Group gap={4}>
                      {e.features.map((f) => (
                        <Badge key={f} size="xs" variant="outline" color="gray">
                          {f}
                        </Badge>
                      ))}
                    </Group>
                  ) : (
                    "-"
                  ),
                ],
              ]}
            />
          ) : (
            <Text size="sm" c="dimmed">
              No engine information reported.
            </Text>
          )}
        </Card>
        <Card withBorder>
          <Title order={5} mb="sm">
            Identity
          </Title>
          <InfoGrid
            labelWidth={110}
            items={[
              ["Fingerprint", <CopyText value={n.fingerprint} />],
              ["Public key", <CopyText value={n.publicKey} />],
            ]}
          />
        </Card>
        <Card withBorder>
          <Title order={5} mb="sm">
            Agent log queue
          </Title>
          {q ? (
            <Stack gap={6}>
              <Group justify="space-between">
                <Text size="sm" c="dimmed">
                  Usage
                </Text>
                <Text size="sm">
                  {formatBytes(q.bytes)} / {formatBytes(q.capacityBytes)}
                </Text>
              </Group>
              <Progress value={qPct} color={qPct > 80 ? "red" : "blue"} />
              <Group justify="space-between">
                <Text size="sm" c="dimmed">
                  Sent records
                </Text>
                <Text size="sm">{formatNumber(q.sentRecords)}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="sm" c="dimmed">
                  Dropped records
                </Text>
                <Text size="sm" c={toNumber(q.droppedRecords) > 0 ? "red" : undefined}>
                  {formatNumber(q.droppedRecords)}
                </Text>
              </Group>
            </Stack>
          ) : (
            <Text size="sm" c="dimmed">
              Not reported (node offline).
            </Text>
          )}
        </Card>
      </SimpleGrid>
    </Stack>
  );
}
