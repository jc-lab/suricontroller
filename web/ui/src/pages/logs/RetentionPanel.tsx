import { useState } from "react";
import { Button, Card, Group, NumberInput, SegmentedControl, SimpleGrid, Stack, Switch, Text, Title } from "@mantine/core";
import { IconDeviceFloppy } from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { api } from "../../api/client";
import { RotateInterval } from "../../gen/suricontroller/api/v1/api_pb";
import type { RetentionPolicy } from "../../gen/suricontroller/api/v1/api_pb";
import { ByteSizeInput } from "../../components/ByteSizeInput";
import { ErrorAlert, LoadingBlock } from "../../components/common";

interface Form {
  rotate: RotateInterval;
  maxSegmentBytes: bigint;
  maxAgeHours: number;
  maxBytesPerNode: bigint;
  maxTotalBytes: bigint;
  compress: boolean;
}

function toForm(p: RetentionPolicy | undefined): Form {
  return {
    rotate: p?.rotate === RotateInterval.DAILY ? RotateInterval.DAILY : RotateInterval.HOURLY,
    maxSegmentBytes: p?.maxSegmentBytes ?? 0n,
    maxAgeHours: p?.maxAgeHours ?? 0,
    maxBytesPerNode: p?.maxBytesPerNode ?? 0n,
    maxTotalBytes: p?.maxTotalBytes ?? 0n,
    compress: p?.compress ?? false,
  };
}

function same(a: Form, b: Form): boolean {
  return (
    a.rotate === b.rotate &&
    a.maxSegmentBytes === b.maxSegmentBytes &&
    a.maxAgeHours === b.maxAgeHours &&
    a.maxBytesPerNode === b.maxBytesPerNode &&
    a.maxTotalBytes === b.maxTotalBytes &&
    a.compress === b.compress
  );
}

function RetentionForm({ policy }: { policy?: RetentionPolicy }) {
  const qc = useQueryClient();
  const initial = toForm(policy);
  const [form, setForm] = useState<Form>(initial);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));
  const dirty = !same(form, initial);
  const save = useMutation({
    mutationFn: () => api.logs.setRetentionPolicy({ policy: { ...form } }),
    meta: { errorTitle: "Failed to save the retention policy" },
    onSuccess: (r) => {
      qc.setQueryData(["retention"], r.policy);
      notifications.show({ color: "green", message: "Retention policy saved" });
    },
  });
  const days = form.maxAgeHours / 24;
  return (
    <Card withBorder maw={820}>
      <Title order={5} mb="sm">
        Rotation and retention of stored logs
      </Title>
      <Stack>
        <div>
          <Text size="sm" fw={500} mb={4}>
            Rotate segments
          </Text>
          <SegmentedControl
            value={String(form.rotate)}
            onChange={(v) => set("rotate", Number(v) as RotateInterval)}
            data={[
              { value: String(RotateInterval.HOURLY), label: "Hourly" },
              { value: String(RotateInterval.DAILY), label: "Daily" },
            ]}
          />
        </div>
        <SimpleGrid cols={{ base: 1, sm: 2 }}>
          <ByteSizeInput
            label="Max segment size"
            description="Rotate a segment early at this size"
            zeroLabel="0 = no limit"
            value={form.maxSegmentBytes}
            onChange={(v) => set("maxSegmentBytes", v)}
          />
          <NumberInput
            label="Max age (hours)"
            description={
              form.maxAgeHours === 0
                ? "Delete older segments (0 = keep forever)"
                : `Delete segments older than ${Number.isInteger(days) ? days : days.toFixed(1)} day(s)`
            }
            min={0}
            allowDecimal={false}
            allowNegative={false}
            value={form.maxAgeHours}
            onChange={(v) => set("maxAgeHours", Number(v) || 0)}
          />
          <ByteSizeInput
            label="Max size per node"
            description="Oldest segments are deleted above this"
            zeroLabel="0 = no limit"
            units={["MiB", "GiB", "TiB"]}
            value={form.maxBytesPerNode}
            onChange={(v) => set("maxBytesPerNode", v)}
          />
          <ByteSizeInput
            label="Max total size"
            description="Across all nodes"
            zeroLabel="0 = no limit"
            units={["MiB", "GiB", "TiB"]}
            value={form.maxTotalBytes}
            onChange={(v) => set("maxTotalBytes", v)}
          />
        </SimpleGrid>
        <Switch
          label="Compress closed segments (zstd)"
          checked={form.compress}
          onChange={(e) => set("compress", e.currentTarget.checked)}
        />
        <Group justify="flex-end">
          <Button variant="default" disabled={!dirty} onClick={() => setForm(initial)}>
            Reset
          </Button>
          <Button leftSection={<IconDeviceFloppy size={16} />} disabled={!dirty} loading={save.isPending} onClick={() => save.mutate()}>
            Save
          </Button>
        </Group>
      </Stack>
    </Card>
  );
}

export function RetentionPanel() {
  const q = useQuery({
    queryKey: ["retention"],
    queryFn: async () => (await api.logs.getRetentionPolicy({})).policy,
    refetchOnWindowFocus: false,
  });
  if (q.isPending) return <LoadingBlock />;
  if (q.isError) return <ErrorAlert error={q.error} onRetry={() => q.refetch()} />;
  const p = q.data;
  const key = p
    ? [p.rotate, p.maxSegmentBytes, p.maxAgeHours, p.maxBytesPerNode, p.maxTotalBytes, p.compress].map(String).join(":")
    : "none";
  return <RetentionForm key={key} policy={p} />;
}
