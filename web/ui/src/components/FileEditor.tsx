import { useEffect, useRef, useState, type ReactNode } from "react";
import { Alert, Badge, Button, Card, Group, Modal, Stack, Text, TextInput, Tooltip } from "@mantine/core";
import { IconAlertTriangle, IconDeviceFloppy, IconGitCommit, IconRefresh, IconTrash } from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { notifications } from "@mantine/notifications";
import { api } from "../api/client";
import { Code, errorMessage, isCode, isConflict, isNoChanges } from "../api/errors";
import { Repo } from "../gen/suricontroller/api/v1/api_pb";
import type { Commit } from "../gen/suricontroller/api/v1/api_pb";
import { decodeText, encodeText, shortCommit } from "../lib/format";
import { CodeEditor, languageForPath } from "./CodeEditor";
import { CommitId, ErrorAlert, LoadingBlock } from "./common";

export interface FileEditorProps {
  repo: Repo;
  path: string;
  /** The file does not exist yet; it is created on save. */
  isNew?: boolean;
  /** Head commit to base a new file on ("" for an empty repository). */
  headCommit?: string;
  initialContent?: string;
  onSaved?: (commit: Commit) => void;
  onDeleted?: () => void;
  onDirtyChange?: (dirty: boolean) => void;
  toolbar?: ReactNode;
  help?: ReactNode;
}

function WriteError({ error, newFile, onReload }: { error: unknown; newFile?: boolean; onReload: () => void }) {
  if (isConflict(error)) {
    return (
      <Alert color="orange" icon={<IconAlertTriangle size={18} />} title="Conflict: the repository changed">
        <Text size="sm">
          {newFile
            ? "Someone committed to the repository after you started this file, so it was not saved. Update to the latest commit (your content is kept unless the file was created meanwhile) and commit again."
            : "Someone committed to the repository after you opened this file, so your change was not saved. Reload the file to get the latest version (your edits are discarded; copy them first if needed)."}
        </Text>
        <Button size="xs" mt="xs" color="orange" variant="light" leftSection={<IconRefresh size={14} />} onClick={onReload}>
          {newFile ? "Update to the latest commit" : "Reload latest version"}
        </Button>
      </Alert>
    );
  }
  if (isNoChanges(error)) {
    return (
      <Alert color="blue" title="Nothing to commit">
        The content is identical to the committed version.
      </Alert>
    );
  }
  if (isCode(error, Code.InvalidArgument)) {
    return (
      <Alert color="red" icon={<IconAlertTriangle size={18} />} title="Validation failed">
        <Text size="sm" ff="monospace" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {errorMessage(error)}
        </Text>
      </Alert>
    );
  }
  return <ErrorAlert error={error} title="Commit failed" />;
}

/** Editor for one file of a git repository, committing with WriteFiles. */
export function FileEditor(props: FileEditorProps) {
  const { repo, path, isNew } = props;
  const qc = useQueryClient();
  const file = useQuery({
    queryKey: ["file", repo, path],
    queryFn: () => api.repo.readFile({ repo, path }),
    enabled: !isNew,
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const [state, setState] = useState<{ base: string; original: string; content: string; created: boolean } | null>(
    isNew ? { base: props.headCommit ?? "", original: "", content: props.initialContent ?? "", created: false } : null,
  );
  const [message, setMessage] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [deleteMessage, setDeleteMessage] = useState("");
  const loadedAt = useRef(0);

  // Initialize (or re-initialize after a reload) from the fetched file.
  useEffect(() => {
    if (isNew || !file.data || file.dataUpdatedAt === loadedAt.current) return;
    loadedAt.current = file.dataUpdatedAt;
    const text = decodeText(file.data.content);
    setState({ base: file.data.commit, original: text, content: text, created: true });
  }, [isNew, file.data, file.dataUpdatedAt]);

  const exists = !isNew || !!state?.created;
  const dirty = !!state && (state.content !== state.original || !exists);

  const onDirtyChange = props.onDirtyChange;
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  useEffect(() => {
    if (!dirty) return;
    const h = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [dirty]);

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["tree", repo] });
    void qc.invalidateQueries({ queryKey: ["commits", repo] });
    void qc.invalidateQueries({ queryKey: ["policies"] });
  };

  const save = useMutation({
    mutationFn: (v: { content: string; base: string; message: string }) =>
      api.repo.writeFiles({
        repo,
        baseCommit: v.base,
        message: v.message,
        changes: [{ path, content: encodeText(v.content) }],
      }),
    meta: { silent: true },
    onSuccess: (r, v) => {
      const id = r.commit?.id ?? "";
      setState((s) => (s ? { ...s, base: id, original: v.content, created: true } : s));
      setMessage("");
      qc.setQueryData(["file", repo, path], { commit: id, content: encodeText(v.content) });
      // The editor state is already up to date; do not re-initialize from the cache.
      loadedAt.current = qc.getQueryState(["file", repo, path])?.dataUpdatedAt ?? loadedAt.current;
      invalidate();
      notifications.show({ color: "green", title: "Committed", message: `${path} saved in ${shortCommit(id)}` });
      if (r.commit) props.onSaved?.(r.commit);
    },
  });

  const del = useMutation({
    mutationFn: (msg: string) =>
      api.repo.writeFiles({
        repo,
        baseCommit: state?.base ?? "",
        message: msg,
        changes: [{ path, delete: true }],
      }),
    meta: { silent: true },
    onSuccess: (r) => {
      setDeleting(false);
      qc.removeQueries({ queryKey: ["file", repo, path] });
      invalidate();
      notifications.show({ color: "green", title: "Deleted", message: `${path} deleted in ${shortCommit(r.commit?.id)}` });
      props.onDeleted?.();
    },
  });

  const reload = async () => {
    save.reset();
    del.reset();
    if (isNew && !state?.created) {
      // New file: someone may have created it meanwhile; otherwise keep the
      // content and move the base to the current head.
      try {
        const r = await api.repo.readFile({ repo, path });
        const text = decodeText(r.content);
        setState({ base: r.commit, original: text, content: text, created: true });
        notifications.show({ color: "orange", message: `${path} was created by someone else; showing their version.` });
      } catch (e) {
        if (!isCode(e, Code.NotFound)) {
          notifications.show({ color: "red", title: "Reload failed", message: errorMessage(e) });
          return;
        }
        const head = await api.repo
          .listCommits({ repo, limit: 1 })
          .then((r) => r.head)
          .catch(() => "");
        setState((s) => (s ? { ...s, base: head } : s));
      }
      invalidate();
      return;
    }
    loadedAt.current = 0;
    const r = await file.refetch();
    if (r.data) {
      loadedAt.current = r.dataUpdatedAt;
      const text = decodeText(r.data.content);
      setState({ base: r.data.commit, original: text, content: text, created: true });
    }
  };

  if (!isNew && file.isPending) return <LoadingBlock label={`Loading ${path}...`} />;
  if (!isNew && file.isError) return <ErrorAlert error={file.error} title={`Cannot read ${path}`} onRetry={() => file.refetch()} />;
  if (!state) return <LoadingBlock />;

  const canSave = dirty && message.trim() !== "" && !save.isPending;

  return (
    <Stack gap="sm">
      <Card withBorder padding="sm">
        <Group justify="space-between" wrap="wrap" gap="xs">
          <Group gap="xs">
            <Text fw={600} ff="monospace">
              {path}
            </Text>
            {!exists && (
              <Badge color="teal" variant="light" size="sm">
                new file
              </Badge>
            )}
            {exists && dirty && (
              <Badge color="yellow" variant="light" size="sm">
                unsaved changes
              </Badge>
            )}
            <Tooltip label="Changes are committed on top of this commit" withArrow>
              <Group gap={4}>
                <IconGitCommit size={14} color="var(--mantine-color-dimmed)" />
                <CommitId id={state.base} size="xs" />
              </Group>
            </Tooltip>
          </Group>
          <Group gap="xs">
            {props.toolbar}
            <Tooltip
              label={exists ? "Reload from the repository (discard edits)" : "Base the new file on the latest commit"}
              withArrow
            >
              <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} onClick={() => void reload()}>
                Reload
              </Button>
            </Tooltip>
            {exists && (
              <Button
                size="xs"
                variant="light"
                color="red"
                leftSection={<IconTrash size={14} />}
                onClick={() => {
                  del.reset();
                  setDeleteMessage(`Delete ${path}`);
                  setDeleting(true);
                }}
              >
                Delete
              </Button>
            )}
          </Group>
        </Group>
        {props.help && (
          <Text size="xs" c="dimmed" mt={6}>
            {props.help}
          </Text>
        )}
      </Card>

      <CodeEditor
        value={state.content}
        onChange={(v) => setState((s) => (s ? { ...s, content: v } : s))}
        language={languageForPath(path)}
        height="calc(100vh - 400px)"
        minHeight="280px"
      />

      {save.isError && <WriteError error={save.error} newFile={!exists} onReload={() => void reload()} />}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) save.mutate({ content: state.content, base: state.base, message: message.trim() });
        }}
      >
        <Group align="flex-end" wrap="nowrap">
          <TextInput
            label="Commit message"
            placeholder={exists ? `Update ${path}` : `Add ${path}`}
            value={message}
            onChange={(e) => setMessage(e.currentTarget.value)}
            style={{ flex: 1 }}
            required
          />
          <Button
            type="submit"
            leftSection={<IconDeviceFloppy size={16} />}
            disabled={!canSave}
            loading={save.isPending}
          >
            Commit
          </Button>
        </Group>
        {dirty && message.trim() === "" && (
          <Text size="xs" c="dimmed" mt={4}>
            Enter a commit message to save.
          </Text>
        )}
      </form>

      <Modal opened={deleting} onClose={() => setDeleting(false)} title={`Delete ${path}`}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (deleteMessage.trim()) del.mutate(deleteMessage.trim());
          }}
        >
          <Stack>
            <Text size="sm">The file is removed in a new commit. It stays available in the history.</Text>
            <TextInput
              label="Commit message"
              value={deleteMessage}
              onChange={(e) => setDeleteMessage(e.currentTarget.value)}
              required
              data-autofocus
            />
            {del.isError && <WriteError error={del.error} onReload={() => { setDeleting(false); void reload(); }} />}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setDeleting(false)}>
                Cancel
              </Button>
              <Button type="submit" color="red" loading={del.isPending} disabled={!deleteMessage.trim()}>
                Delete file
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
