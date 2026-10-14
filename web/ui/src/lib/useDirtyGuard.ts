import { useCallback, useRef } from "react";
import { modals } from "@mantine/modals";

/** Asks for confirmation before discarding unsaved editor changes. */
export function useDirtyGuard() {
  const dirty = useRef(false);
  const setDirty = useCallback((d: boolean) => {
    dirty.current = d;
  }, []);
  const guard = useCallback((action: () => void) => {
    if (!dirty.current) {
      action();
      return;
    }
    modals.openConfirmModal({
      title: "Discard unsaved changes?",
      children: "The current file has changes that are not committed.",
      labels: { confirm: "Discard", cancel: "Keep editing" },
      confirmProps: { color: "red" },
      onConfirm: () => {
        dirty.current = false;
        action();
      },
    });
  }, []);
  return { setDirty, guard };
}
