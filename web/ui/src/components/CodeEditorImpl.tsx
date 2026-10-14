import { useMemo } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { EditorView } from "@codemirror/view";
import { yaml } from "@codemirror/lang-yaml";
import { useComputedColorScheme } from "@mantine/core";
import type { CodeEditorProps } from "./CodeEditor";

const baseTheme = EditorView.theme({
  "&": { fontSize: "13px", border: "1px solid var(--mantine-color-default-border)", borderRadius: "4px" },
  "&.cm-focused": { outline: "none", borderColor: "var(--mantine-primary-color-filled)" },
  ".cm-scroller": { fontFamily: "var(--mantine-font-family-monospace)" },
});

export default function CodeEditorImpl(props: CodeEditorProps) {
  const scheme = useComputedColorScheme("light");
  const extensions = useMemo(() => {
    const ext = [baseTheme];
    if (props.language === "yaml") ext.push(yaml());
    if (props.wrap) ext.push(EditorView.lineWrapping);
    return ext;
  }, [props.language, props.wrap]);
  return (
    <CodeMirror
      value={props.value}
      onChange={props.onChange}
      readOnly={props.readOnly}
      editable={!props.readOnly}
      height={props.height ?? "480px"}
      minHeight={props.minHeight}
      maxHeight={props.maxHeight}
      theme={scheme === "dark" ? "dark" : "light"}
      extensions={extensions}
      basicSetup={{ foldGutter: props.language === "yaml", highlightActiveLine: !props.readOnly, autocompletion: false }}
      placeholder={props.placeholder}
    />
  );
}
