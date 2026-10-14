import { lazy, Suspense, type ReactNode } from "react";
import { createHashRouter, Navigate } from "react-router";
import { AppLayout } from "./components/AppLayout";
import { RequireAuth } from "./components/RequireAuth";
import { LoadingBlock } from "./components/common";
import { LoginPage } from "./pages/LoginPage";
import { RouteError } from "./components/RouteError";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const NodesPage = lazy(() => import("./pages/NodesPage"));
const NodeDetailPage = lazy(() => import("./pages/NodeDetailPage"));
const RulesPage = lazy(() => import("./pages/RulesPage"));
const ConfigPage = lazy(() => import("./pages/ConfigPage"));
const DeployPage = lazy(() => import("./pages/DeployPage"));
const LogsPage = lazy(() => import("./pages/LogsPage"));
const SystemPage = lazy(() => import("./pages/SystemPage"));

function page(el: ReactNode) {
  return <Suspense fallback={<LoadingBlock h={300} />}>{el}</Suspense>;
}

export const router = createHashRouter([
  { path: "/login", element: <LoginPage />, errorElement: <RouteError /> },
  {
    path: "/",
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    errorElement: <RouteError />,
    children: [
      { index: true, element: page(<DashboardPage />) },
      { path: "nodes", element: page(<NodesPage />) },
      { path: "nodes/:id", element: page(<NodeDetailPage />) },
      { path: "rules", element: page(<RulesPage />) },
      { path: "config", element: page(<ConfigPage />) },
      { path: "deploy", element: page(<DeployPage />) },
      { path: "logs", element: page(<LogsPage />) },
      { path: "system", element: page(<SystemPage />) },
      { path: "*", element: <Navigate to="/" replace /> },
    ],
  },
]);
