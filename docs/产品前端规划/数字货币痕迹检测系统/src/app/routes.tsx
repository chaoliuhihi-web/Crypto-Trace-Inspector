import { createBrowserRouter } from "react-router";
import { Layout } from "./components/Layout";
import CaseInfo from "./pages/CaseInfo";
import DeviceConnection from "./pages/DeviceConnection";
import DataCollection from "./pages/DataCollection";
import RuleMatching from "./pages/RuleMatching";
import HitAnalysis from "./pages/HitAnalysis";
import EvidenceManagement from "./pages/EvidenceManagement";
import ReportGeneration from "./pages/ReportGeneration";
import AuditVerification from "./pages/AuditVerification";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      {
        index: true,
        element: <CaseInfo />,
      },
      {
        path: "device",
        element: <DeviceConnection />,
      },
      {
        path: "collection",
        element: <DataCollection />,
      },
      {
        path: "rules",
        element: <RuleMatching />,
      },
      {
        path: "analysis",
        element: <HitAnalysis />,
      },
      {
        path: "evidence",
        element: <EvidenceManagement />,
      },
      {
        path: "report",
        element: <ReportGeneration />,
      },
      {
        path: "audit",
        element: <AuditVerification />,
      },
    ],
  },
]);