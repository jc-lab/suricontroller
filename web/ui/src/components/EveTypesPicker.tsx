import { useState } from "react";
import { ActionIcon, Button, Checkbox, Group, Popover, ScrollArea, SimpleGrid, Stack, Switch, Text, TextInput } from "@mantine/core";
import { IconChevronDown, IconPlus } from "@tabler/icons-react";
import type { PolicyDraft } from "../lib/logPolicy";
import { eveSummary } from "../lib/logPolicy";

interface Props {
  draft: PolicyDraft;
  suggestions: string[];
  reported?: string[];
  disabled?: boolean;
  onChange: (d: PolicyDraft) => void;
}

/** Inline editor for eve_all_types / eve_types. */
export function EveTypesEditor({ draft, suggestions, reported, disabled, onChange }: Props) {
  const [custom, setCustom] = useState("");
  const all = [...new Set([...suggestions, ...draft.eveTypes])].sort();
  const addCustom = () => {
    const v = custom.trim();
    if (!v) return;
    if (!draft.eveTypes.includes(v)) onChange({ ...draft, eveTypes: [...draft.eveTypes, v] });
    setCustom("");
  };
  return (
    <Stack gap="xs">
      <Switch
        label="Collect all event types"
        checked={draft.eveAllTypes}
        disabled={disabled}
        onChange={(e) => onChange({ ...draft, eveAllTypes: e.currentTarget.checked })}
      />
      {!draft.eveAllTypes && (
        <>
          <Group gap="xs">
            <Button
              size="compact-xs"
              variant="light"
              disabled={disabled}
              onClick={() => onChange({ ...draft, eveTypes: all })}
            >
              Select all
            </Button>
            <Button
              size="compact-xs"
              variant="light"
              color="gray"
              disabled={disabled}
              onClick={() => onChange({ ...draft, eveTypes: [] })}
            >
              None
            </Button>
          </Group>
          <ScrollArea.Autosize mah={220} type="auto">
            <Checkbox.Group value={draft.eveTypes} onChange={(v) => onChange({ ...draft, eveTypes: v })}>
              <SimpleGrid cols={2} spacing={6} verticalSpacing={6}>
                {all.map((t) => (
                  <Checkbox
                    key={t}
                    value={t}
                    size="xs"
                    disabled={disabled}
                    label={
                      reported?.includes(t) ? (
                        <span>
                          {t}{" "}
                          <Text span size="xs" c="teal">
                            (reported)
                          </Text>
                        </span>
                      ) : (
                        t
                      )
                    }
                  />
                ))}
              </SimpleGrid>
            </Checkbox.Group>
          </ScrollArea.Autosize>
          <Group gap={4} wrap="nowrap">
            <TextInput
              size="xs"
              placeholder="Other event type"
              value={custom}
              disabled={disabled}
              onChange={(e) => setCustom(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addCustom();
                }
              }}
              style={{ flex: 1 }}
            />
            <ActionIcon variant="light" onClick={addCustom} disabled={disabled || !custom.trim()} aria-label="Add">
              <IconPlus size={14} />
            </ActionIcon>
          </Group>
          {draft.eveTypes.length === 0 && (
            <Text size="xs" c="orange">
              No event types selected: no EVE events will be collected.
            </Text>
          )}
        </>
      )}
    </Stack>
  );
}

/** Compact button + popover version of EveTypesEditor (for the matrix). */
export function EveTypesPicker(props: Props) {
  return (
    <Popover width={320} position="bottom-start" withArrow shadow="md" trapFocus>
      <Popover.Target>
        <Button
          size="compact-xs"
          variant="default"
          rightSection={<IconChevronDown size={12} />}
          disabled={props.disabled}
          styles={{ label: { maxWidth: 170, overflow: "hidden", textOverflow: "ellipsis" } }}
        >
          {eveSummary(props.draft)}
        </Button>
      </Popover.Target>
      <Popover.Dropdown>
        <EveTypesEditor {...props} />
      </Popover.Dropdown>
    </Popover>
  );
}
