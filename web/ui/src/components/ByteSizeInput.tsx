import { useState } from "react";
import { Group, NumberInput, Select } from "@mantine/core";

const UNIT_BYTES: Record<string, number> = { KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3, TiB: 1024 ** 4 };

function pickUnit(bytes: bigint, units: string[]): string {
  for (let i = units.length - 1; i >= 0; i--) {
    const u = units[i]!;
    const b = BigInt(UNIT_BYTES[u]!);
    if (bytes >= b && bytes % b === 0n) return u;
  }
  return units[0]!;
}

/** Byte size input with a unit selector; the value is in bytes. */
export function ByteSizeInput(props: {
  label: string;
  description?: string;
  value: bigint;
  onChange: (bytes: bigint) => void;
  units?: string[];
  zeroLabel?: string;
}) {
  const units = props.units ?? ["MiB", "GiB"];
  const [unit, setUnit] = useState(() => pickUnit(props.value, units));
  const unitBytes = UNIT_BYTES[unit]!;
  const display = Number(props.value) / unitBytes;
  return (
    <Group gap={6} align="flex-end" wrap="nowrap">
      <NumberInput
        label={props.label}
        description={props.value === 0n && props.zeroLabel ? `${props.description ?? ""} (${props.zeroLabel})` : props.description}
        value={Number.isInteger(display) ? display : Number(display.toFixed(3))}
        min={0}
        allowNegative={false}
        thousandSeparator=","
        onChange={(v) => props.onChange(BigInt(Math.max(0, Math.round((Number(v) || 0) * unitBytes))))}
        style={{ flex: 1 }}
      />
      <Select
        data={units}
        value={unit}
        onChange={(u) => u && setUnit(u)}
        allowDeselect={false}
        w={90}
        aria-label={`${props.label} unit`}
      />
    </Group>
  );
}
