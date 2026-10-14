import { useMemo, useState } from "react";
import { Button, Paper, ScrollArea, Text } from "@mantine/core";
import classes from "./DiffView.module.css";

const MAX_LINES = 5000;

function lineClass(line: string): string {
  if (line.startsWith("diff --git") || line.startsWith("index ")) return classes.file;
  if (line.startsWith("+++") || line.startsWith("---")) return classes.fileName;
  if (line.startsWith("@@")) return classes.hunk;
  if (line.startsWith("+")) return classes.add;
  if (line.startsWith("-")) return classes.del;
  if (line.startsWith("\\") || line.startsWith("...")) return classes.meta;
  return classes.ctx;
}

/** Renders unified diff text with +/- line coloring. */
export function DiffView(props: { diff: string; maxHeight?: number | string }) {
  const [limit, setLimit] = useState(MAX_LINES);
  const lines = useMemo(() => {
    const l = props.diff.split("\n");
    if (l.length && l[l.length - 1] === "") l.pop();
    return l;
  }, [props.diff]);
  if (!lines.length) {
    return (
      <Text size="sm" c="dimmed" py="md">
        No textual changes.
      </Text>
    );
  }
  const shown = lines.length > limit ? lines.slice(0, limit) : lines;
  return (
    <Paper withBorder radius="sm" className={classes.root}>
      <ScrollArea.Autosize mah={props.maxHeight ?? 600} type="auto">
        <pre className={classes.pre}>
          {shown.map((l, i) => (
            <div key={i} className={lineClass(l)}>
              {l || " "}
            </div>
          ))}
        </pre>
      </ScrollArea.Autosize>
      {lines.length > limit && (
        <Button variant="subtle" size="xs" fullWidth onClick={() => setLimit((n) => n + MAX_LINES)}>
          Show more ({(lines.length - limit).toLocaleString()} more lines)
        </Button>
      )}
    </Paper>
  );
}
