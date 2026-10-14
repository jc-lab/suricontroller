import { Tabs } from "@mantine/core";
import { useSearchParams } from "react-router";
import { PageHeader } from "../components/common";
import { CollectionMatrix } from "./logs/CollectionMatrix";
import { RetentionPanel } from "./logs/RetentionPanel";
import { IngestPanel } from "./logs/IngestPanel";
import { BrowserPanel } from "./logs/BrowserPanel";

export default function LogsPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "collection";
  return (
    <>
      <PageHeader title="Logs" description="Collection policy, retention, ingest statistics and stored logs" />
      <Tabs
        value={tab}
        onChange={(v) => {
          const p = new URLSearchParams(params);
          p.set("tab", v || "collection");
          setParams(p, { replace: true });
        }}
        keepMounted={false}
      >
        <Tabs.List mb="md">
          <Tabs.Tab value="collection">Collection policy</Tabs.Tab>
          <Tabs.Tab value="retention">Retention</Tabs.Tab>
          <Tabs.Tab value="ingest">Ingest</Tabs.Tab>
          <Tabs.Tab value="browser">Browser &amp; tail</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="collection">
          <CollectionMatrix />
        </Tabs.Panel>
        <Tabs.Panel value="retention">
          <RetentionPanel />
        </Tabs.Panel>
        <Tabs.Panel value="ingest">
          <IngestPanel />
        </Tabs.Panel>
        <Tabs.Panel value="browser">
          <BrowserPanel />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
