import {
  LayoutDashboard,
  ScanLine,
  FileCode2,
  Globe,
  Network,
  ListTodo,
  Package,
  Activity,
  Settings,
  Users,
  Bell,
  History,
  FolderGit2,
} from "lucide-react";
export const nav = [
  ["dashboard", "Overview", LayoutDashboard],
  ["content", "Detection as code", FolderGit2],
  ["yara_rules", "Signatures", FileCode2],
  ["c2ips", "IP indicators", Network],
  ["c2dns", "Domain indicators", Globe],
  ["tasks", "Review tasks", ListTodo],
  ["scanner", "Sample lab", ScanLine],
  ["releases", "Releases", Package],
  ["jobs", "Background jobs", Activity],
  ["activity_log", "Activity", History],
  ["settings", "Configuration", Settings],
  ["bookmarks", "Following", Bell],
  ["account", "My account", Users],
] as const;
export const title = (page: string) =>
  nav.find((n) => n[0] === page)?.[1] || "Overview";
export const entityNames: any = {
  yara_rules: "signature",
  c2ips: "IP indicator",
  c2dns: "domain indicator",
  tasks: "task",
};
