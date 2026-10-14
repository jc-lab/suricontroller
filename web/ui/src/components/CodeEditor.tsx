import { lazy, Suspense } from "react";
import { LoadingBlock } from "./common";

export interface CodeEditorProps {
  value: string;
  onChange?: (value: string) => void;
  language?: "yaml" | "text";
  readOnly?: boolean;
  height?: string;
  minHeight?: string;
  maxHeight?: string;
  wrap?: boolean;
  placeholder?: string;
}

// CodeMirror is loaded on demand to keep the initial bundle small.
const Impl = lazy(() => import("./CodeEditorImpl"));

export function CodeEditor(props: CodeEditorProps) {
  return (
    <Suspense fallback={<LoadingBlock label="Loading editor..." h={props.height ?? 240} />}>
      <Impl {...props} />
    </Suspense>
  );
}

export function languageForPath(path: string): "yaml" | "text" {
  return /\.ya?ml$/i.test(path) ? "yaml" : "text";
}
