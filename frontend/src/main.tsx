import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield,
  LayoutDashboard,
  ScanLine,
  FileCode2,
  Globe,
  Network,
  ListTodo,
  Package,
  Activity,
  Settings,
  Tags,
  Users,
  Bell,
  Search,
  Plus,
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  Check,
  GitBranch,
  LogOut,
  Menu,
  X,
  Upload,
  Download,
  Play,
  RefreshCw,
  Trash2,
  History,
  Code2,
  CheckCircle2,
  AlertCircle,
  FolderGit2,
  ChevronDown,
  Loader2,
  ExternalLink,
} from "lucide-react";
import "./style.css";
const base = "/ThreatKB";
async function api(path: string, options: any = {}) {
  const r = await fetch(base + path, {
    credentials: "same-origin",
    ...options,
    headers:
      options.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json", ...options.headers },
  });
  const text = await r.text();
  let value: any;
  try {
    value = text ? JSON.parse(text) : null;
  } catch {
    value = text;
  }
  if (r.status === 401 && path !== "/login" && path !== "/users/me")
    window.dispatchEvent(new Event("threatkb:unauthorized"));
  if (!r.ok)
    throw new Error(
      typeof value === "object"
        ? value?.error || value?.message || `Request failed (${r.status})`
        : value || `Request failed (${r.status})`,
    );
  return value;
}
const write = (path: string, data: any, method = "POST") =>
  api(path, { method, body: JSON.stringify(data) });
const fmt = (n: any) => Number(n || 0).toLocaleString();
const date = (v: any) =>
  v
    ? new Date(v.endsWith?.("Z") ? v : v + "Z").toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      })
    : "—";
const nav = [
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
const title = (page: string) =>
  nav.find((n) => n[0] === page)?.[1] || "Overview";
function Badge({ value }: any) {
  return (
    <span
      className={
        "badge " +
        String(value || "")
          .toLowerCase()
          .replaceAll(" ", "-")
      }
    >
      {value || "Unassigned"}
    </span>
  );
}
function IconButton({ label, children, onClick }: any) {
  return (
    <button
      className="icon-button"
      title={label}
      aria-label={label}
      onClick={onClick}
    >
      {children}
    </button>
  );
}
function Empty({ text = "No records to show.", children }: any) {
  return (
    <div className="empty">
      <Shield size={28} />
      <h3>{text}</h3>
      {children}
    </div>
  );
}
function Dialog({ title, children, onClose, wide = false }: any) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  return (
    <dialog
      ref={ref}
      className={wide ? "wide" : ""}
      onCancel={onClose}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
    >
      <div className="dialog-head">
        <div>
          <span className="eyebrow">WORKSPACE</span>
          <h2>{title}</h2>
        </div>
        <IconButton label="Close dialog" onClick={onClose}>
          <X />
        </IconButton>
      </div>
      {children}
    </dialog>
  );
}
function Login({ onLogin, notify }: any) {
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <main className="login">
      <div className="login-story">
        <div className="brand">
          <span className="brand-icon">
            <Shield />
          </span>
          ThreatKB
        </div>
        <div>
          <span className="eyebrow">DETECTION ENGINEERING</span>
          <h1>
            From a signal <br />
            to a stronger <br />
            <em>defense.</em>
          </h1>
          <p>
            Your signatures, intelligence and release workflows. <br />
            One focused workspace.
          </p>
        </div>
        <span className="login-footer">
          Built for the people behind the detections.
        </span>
      </div>
      <section className="login-form">
        <div>
          <span className="eyebrow">WELCOME BACK</span>
          <h2>Sign in to your workspace</h2>
          <p className="muted">Continue your detection engineering work.</p>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                const r = await write("/login", { email, password });
                onLogin(r.user);
              } catch (err: any) {
                notify(err.message, true);
              } finally {
                setBusy(false);
              }
            }}
          >
            <label>
              Email address
              <input
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoFocus
              />
            </label>
            <label>
              Password
              <input
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <button className="primary full" disabled={busy}>
              {busy ? <Loader2 className="spin" size={17} /> : null}Sign in{" "}
              <ArrowUpRight size={17} />
            </button>
          </form>
          <p className="help">
            Need access? Contact your workspace administrator.
          </p>
        </div>
      </section>
    </main>
  );
}
function App() {
  const [user, setUser] = useState<any>(undefined),
    [page, setPage] = useState(
      location.hash.replace(/^#!?\//, "").split("?")[0] || "dashboard",
    ),
    [notice, setNotice] = useState<any>(null),
    [mobile, setMobile] = useState(false),
    [narrow, setNarrow] = useState(
      window.matchMedia("(max-width: 800px)").matches,
    ),
    [notifications, setNotifications] = useState<any>(null),
    [unread, setUnread] = useState(0),
    [version, setVersion] = useState(0),
    [query, setQuery] = useState("");
  useEffect(() => {
    const media = window.matchMedia("(max-width: 800px)");
    const change = () => setNarrow(media.matches);
    media.addEventListener("change", change);
    return () => media.removeEventListener("change", change);
  }, []);
  useEffect(() => {
    if (!mobile) return;
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobile(false);
    };
    window.addEventListener("keydown", escape);
    return () => window.removeEventListener("keydown", escape);
  }, [mobile]);
  const notify = (message: string, error = false) => {
    setNotice({ message, error });
    setTimeout(() => setNotice(null), 7000);
  };
  const go = (next: string) => {
    location.hash = "/" + next;
    setMobile(false);
    setQuery("");
  };
  useEffect(() => {
    api("/users/me")
      .then(setUser)
      .catch(() => {
        sessionStorage.setItem("threatkb.returnTo", location.hash);
        setUser(null);
      });
    const fn = () =>
      setPage(location.hash.replace(/^#!?\//, "").split("?")[0] || "dashboard");
    const expired = () => {
      sessionStorage.setItem("threatkb.returnTo", location.hash);
      setUser(null);
    };
    window.addEventListener("hashchange", fn);
    window.addEventListener("threatkb:unauthorized", expired);
    return () => {
      window.removeEventListener("hashchange", fn);
      window.removeEventListener("threatkb:unauthorized", expired);
    };
  }, []);
  useEffect(() => {
    if (!user) return;
    const poll = () =>
      api("/notifications")
        .then((r) => setUnread(r.unread_count))
        .catch(() => {});
    poll();
    const t = setInterval(poll, 30000);
    return () => clearInterval(t);
  }, [user, version]);
  if (user === undefined)
    return (
      <div className="boot">
        <Shield />
        <span>Opening your workspace…</span>
      </div>
    );
  if (!user)
    return (
      <>
        <Login
          notify={notify}
          onLogin={(u: any) => {
            setUser(u);
            const saved = sessionStorage.getItem("threatkb.returnTo");
            sessionStorage.removeItem("threatkb.returnTo");
            go(saved?.startsWith("#/") ? saved.slice(2) : "dashboard");
          }}
        />
        {notice && (
          <div
            className={"toast " + (notice.error ? "error" : "")}
            role="alert"
          >
            {notice.message}
          </div>
        )}
      </>
    );
  const refresh = () => setVersion((v) => v + 1);
  return (
    <div className="app-shell">
      <aside
        inert={narrow && !mobile}
        className={mobile ? "sidebar visible" : "sidebar"}
      >
        <button className="brand" onClick={() => go("dashboard")}>
          <span className="brand-icon">
            <Shield size={24} />
          </span>
          ThreatKB<span className="brand-version">2</span>
        </button>
        <div className="workspace">
          <span className="workspace-dot" />
          <div>
            <strong>Local workspace</strong>
            <small>Detection engineering</small>
          </div>
          <ChevronDown size={15} />
        </div>
        <span className="nav-label">WORKBENCH</span>
        <nav aria-label="Main navigation">
          {nav.map(([key, label, Icon], i) => (
            <React.Fragment key={key}>
              {i === 7 && (
                <span className="nav-label separated">OPERATIONS</span>
              )}
              <button
                className={page === key ? "active" : ""}
                onClick={() => go(key)}
              >
                <Icon size={18} />
                <span>{label}</span>
                {page === key && <span className="active-dot" />}
              </button>
            </React.Fragment>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="git-mark">
            <GitBranch size={15} />
            <span>Git-backed workflows</span>
          </div>
          <button
            className="account"
            onClick={async () => {
              await api("/logout");
              setUser(null);
            }}
          >
            <span className="avatar">
              {user.email.slice(0, 2).toUpperCase()}
            </span>
            <span>
              <strong>{user.first_name || user.email.split("@")[0]}</strong>
              <small>{user.admin ? "Administrator" : "Analyst"}</small>
            </span>
            <LogOut size={16} />
          </button>
        </div>
      </aside>
      {mobile && (
        <button
          className="scrim"
          aria-label="Close navigation"
          onClick={() => setMobile(false)}
        />
      )}
      <div className="main-shell">
        <header className="topbar">
          <IconButton label="Open navigation" onClick={() => setMobile(true)}>
            <Menu size={20} />
          </IconButton>
          <span className="breadcrumb">
            Workspace <span>/</span> <strong>{title(page)}</strong>
          </span>
          <div className="topbar-right">
            <span className="local-status">
              <i />
              Local workspace
            </span>
            <IconButton
              label={`Notifications (${unread} unread)`}
              onClick={async () =>
                setNotifications(await api("/notifications"))
              }
            >
              <Bell size={19} />
              {unread > 0 && <span className="notification-dot" />}
            </IconButton>
            <span className="avatar pale">
              {user.email.slice(0, 2).toUpperCase()}
            </span>
          </div>
        </header>
        <main className="main" key={page}>
          <div className="page-heading">
            <div>
              <span className="eyebrow">
                {page === "dashboard"
                  ? "YOUR WORKSPACE"
                  : "DETECTION WORKSPACE"}
              </span>
              <h1>
                {page === "dashboard" ? "Detection overview" : title(page)}
              </h1>
              <p className="muted">
                {
                  (
                    {
                      dashboard:
                        "A clear view of your content, intelligence and release activity.",
                      content:
                        "Versioned YAML signatures. Reviewed, tested and ready to ship.",
                      yara_rules:
                        "Manage signature content and its complete revision history.",
                      c2ips:
                        "Review and maintain IP-based threat intelligence.",
                      c2dns:
                        "Review and maintain domain-based threat intelligence.",
                      tasks: "Keep analyst reviews moving.",
                      scanner:
                        "Scan samples or generate a draft signature from related files.",
                      releases: "Build and inspect your released content.",
                      jobs: "Follow long-running work from queue to result.",
                      activity_log:
                        "A shared history of changes across the workspace.",
                      settings: "Manage the building blocks of your workspace.",
                    } as any
                  )[page]
                }
              </p>
            </div>
            <IconButton label="Refresh view" onClick={refresh}>
              <RefreshCw size={19} />
            </IconButton>
          </div>
          {page === "dashboard" ? (
            <Dashboard version={version} go={go} />
          ) : page === "content" ? (
            <Content version={version} notify={notify} refresh={refresh} />
          ) : page === "scanner" ? (
            <SampleLab notify={notify} />
          ) : page === "account" ? (
            <Account user={user} notify={notify} />
          ) : page === "bookmarks" ? (
            <Following notify={notify} />
          ) : page === "settings" ? (
            <Configuration notify={notify} refresh={refresh} />
          ) : (
            <Records
              page={page}
              version={version}
              query={query}
              setQuery={setQuery}
              notify={notify}
              refresh={refresh}
            />
          )}
        </main>
        <footer className="main-footer">
          <span>
            <Shield size={13} /> ThreatKB · Detection engineering workspace
          </span>
          <span>Local development workspace</span>
        </footer>
      </div>
      {notice && (
        <div className={"toast " + (notice.error ? "error" : "")} role="alert">
          {notice.error ? (
            <AlertCircle size={18} />
          ) : (
            <CheckCircle2 size={18} />
          )}
          <span>{notice.message}</span>
          <IconButton
            label="Dismiss notification"
            onClick={() => setNotice(null)}
          >
            <X size={16} />
          </IconButton>
        </div>
      )}
      {notifications && (
        <Dialog
          title="Your notifications"
          onClose={() => setNotifications(null)}
        >
          <div className="dialog-body">
            <div className="section-top">
              <p className="muted">Changes to content you own or follow.</p>
              <button
                onClick={async () => {
                  await write("/notifications/clear", {});
                  setNotifications({ data: [], unread_count: 0 });
                  setUnread(0);
                }}
              >
                Clear notifications
              </button>
            </div>
            {notifications.data.length ? (
              notifications.data.map((n: any) => (
                <article className="activity-row" key={n.id}>
                  <span className="event-icon">
                    <Bell size={17} />
                  </span>
                  <div>
                    <strong>{n.activity_text}</strong>
                    <small>
                      {n.user?.email || "System"} · {date(n.activity_date)}
                    </small>
                  </div>
                </article>
              ))
            ) : (
              <Empty text="You're all caught up." />
            )}
          </div>
        </Dialog>
      )}
    </div>
  );
}
function Dashboard({ version, go }: any) {
  const [data, setData] = useState<any>(null),
    [health, setHealth] = useState<any>(null);
  useEffect(() => {
    api("/dashboard").then(setData);
    api("/ingestion/health").then(setHealth);
  }, [version]);
  if (!data) return <Loading />;
  const cards = [
    ["signatures", "Signatures", FileCode2, "yara_rules"],
    ["ips", "IP indicators", Network, "c2ips"],
    ["domains", "Domain indicators", Globe, "c2dns"],
    ["tasks", "Review tasks", ListTodo, "tasks"],
  ];
  return (
    <>
      {health?.alerts.length > 0 && (
        <div className="banner warning">
          <AlertCircle size={19} />
          <span>
            <strong>Ingestion needs attention.</strong>{" "}
            {health.alerts.map((s: any) => s.name).join(", ")} exceeded the
            expected update window.
          </span>
          <button onClick={() => go("settings")}>
            Review sources <ArrowUpRight size={15} />
          </button>
        </div>
      )}
      <div className="metric-grid">
        {cards.map(([key, label, Icon, target]: any) => (
          <button className="metric-card" key={key} onClick={() => go(target)}>
            <div>
              <span>{label}</span>
              <Icon size={19} />
            </div>
            <strong>{fmt(data.counts[key])}</strong>
            <small>
              Active in your workspace <ArrowUpRight size={13} />
            </small>
          </button>
        ))}
      </div>
      <div className="overview-grid">
        <section className="panel pipeline-panel">
          <div className="section-top">
            <div>
              <span className="eyebrow">DETECTION CONTENT</span>
              <h2>From draft to deployment</h2>
            </div>
            <span className="tag">
              <GitBranch size={13} />
              Versioned content
            </span>
          </div>
          <div className="pipeline-states">
            {["Imported", "Vetting", "Released", "Retired"].map((state, i) => (
              <div key={state}>
                <span className={"step-number step-" + i}>{i + 1}</span>
                <strong>
                  {fmt(data.states.find((s: any) => s.state === state)?.count)}
                </strong>
                <small>{state === "Vetting" ? "In review" : state}</small>
              </div>
            ))}
          </div>
          <div className="panel-bottom">
            <p>
              Every release starts with validated, independently reviewed
              content.
            </p>
            <button className="primary" onClick={() => go("content")}>
              Open content workbench <ArrowUpRight size={16} />
            </button>
          </div>
        </section>
        <section className="panel release-card">
          <span className="eyebrow">RELEASE CONTROL</span>
          <div className="release-icon">
            <Package size={28} />
          </div>
          <h2>
            Confidence before <br />
            production.
          </h2>
          <p>
            Validate samples, observe a testing channel, then promote when
            telemetry is clear.
          </p>
          <button onClick={() => go("releases")}>
            View releases <ArrowUpRight size={16} />
          </button>
          <div className="release-stat">
            <strong>{fmt(data.counts.releases)}</strong>
            <span>recorded releases</span>
            <Badge value={data.counts.running_jobs + " jobs running"} />
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="section-top">
          <div>
            <h2>Recent workspace activity</h2>
            <p className="muted">
              The latest changes across your detection content.
            </p>
          </div>
          <button onClick={() => go("activity_log")}>
            View all activity <ArrowUpRight size={15} />
          </button>
        </div>
        {data.activity.length ? (
          data.activity.map((event: any) => (
            <article className="activity-row" key={event.id}>
              <span className="event-icon">
                <FileCode2 size={18} />
              </span>
              <div>
                <strong>{event.activity_text}</strong>
                <small>
                  {event.user?.email || "System"} · {event.entity_type}
                </small>
              </div>
              <Badge value={event.activity_type} />
              <time>{date(event.activity_date)}</time>
            </article>
          ))
        ) : (
          <Empty text="Activity will appear as your team works." />
        )}
      </section>
    </>
  );
}
function Loading() {
  return (
    <div className="loading" role="status">
      <Loader2 className="spin" size={22} />
      Loading workspace data…
    </div>
  );
}
const entityNames: any = {
  yara_rules: "signature",
  c2ips: "IP indicator",
  c2dns: "domain indicator",
  tasks: "task",
};
function Records({ page, version, query, setQuery, notify, refresh }: any) {
  const [distribution, setDistribution] = useState<any>(null),
    [data, setData] = useState<any>(null),
    [index, setIndex] = useState(0),
    [view, setView] = useState("Active Only"),
    [selected, setSelected] = useState<Set<number>>(new Set()),
    [editor, setEditor] = useState<any>(null),
    [wrap, setWrap] = useState(false),
    [columns, setColumns] = useState<any[]>([]),
    [extra, setExtra] = useState<any>(null);
  const editable = !!entityNames[page];
  useEffect(() => {
    const id = new URLSearchParams(location.hash.split("?")[1] || "").get("id");
    if (id && editable)
      api("/" + page + "/" + id)
        .then(setEditor)
        .catch((e: any) => notify(e.message, true));
  }, [page]);
  useEffect(() => {
    if (page === "activity_log")
      api("/activity_log/distribution").then(setDistribution);
  }, [page, version]);
  useEffect(() => {
    setIndex(0);
    setSelected(new Set());
  }, [query, view, page]);
  useEffect(() => {
    let live = true;
    const column =
      page === "yara_rules"
        ? "name"
        : page === "c2ips"
          ? "ip"
          : page === "c2dns"
            ? "domain_name"
            : page === "tasks"
              ? "title"
              : "";
    const params = new URLSearchParams({
      page_number: String(index),
      page_size: "25",
      limit: "25",
      view,
      short: "true",
    });
    if (query && column)
      params.set("searches", JSON.stringify({ [column]: query }));
    api("/" + page + "?" + params)
      .then((r) => {
        if (live)
          setData(Array.isArray(r) ? { data: r, total_count: r.length } : r);
      })
      .catch((e: any) => notify(e.message, true));
    if (editable)
      api(
        "/metadata/columns?artifact_type=" +
          ({ yara_rules: 1, c2dns: 2, c2ips: 3, tasks: 4 } as any)[page],
      ).then(setColumns);
    return () => {
      live = false;
    };
  }, [page, index, version, query, view]);
  const open = async (row: any) => {
    try {
      if (editable) setEditor(await api("/" + page + "/" + row.id));
      else setExtra(row);
    } catch (e: any) {
      notify(e.message, true);
    }
  };
  return (
    <>
      {page === "activity_log" && distribution && (
        <section className="panel">
          <h2>Activity by analyst</h2>
          <div className="distribution" aria-label="Activity distribution">
            {distribution.users.map((u: any, i: number) => (
              <div
                key={u.id || "system"}
                style={{
                  width: u.percent + "%",
                  background: ["#497143", "#7ca467", "#a0be86", "#c6d5b1"][
                    i % 4
                  ],
                }}
                title={u.email + ": " + u.count}
              />
            ))}
          </div>
          <div className="tag-list">
            {distribution.users.map((u: any) => (
              <span className="tag" key={u.id || "system"}>
                {u.email} · {u.count} ({u.percent}%)
              </span>
            ))}
          </div>
        </section>
      )}
      <section className="panel records-panel">
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search records"
              placeholder={`Search ${title(page).toLowerCase()}…`}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <kbd>⌕</kbd>
          </div>
          <div className="toolbar-actions">
            {editable && (
              <select
                aria-label="Record visibility"
                value={view}
                onChange={(e) => setView(e.target.value)}
              >
                <option>Active Only</option>
                <option>Inactive Only</option>
                <option>All</option>
              </select>
            )}
            <button
              className={wrap ? "selected-button" : ""}
              aria-pressed={wrap}
              aria-controls="records-table"
              onClick={() => setWrap(!wrap)}
            >
              {" "}
              {wrap ? "Compact text" : "Expand text"}
            </button>
            {editable && (
              <button
                className="primary"
                onClick={() =>
                  setEditor({
                    new: true,
                    state: "Vetting",
                    category: "Uncategorized",
                    tags: [],
                    strings: "",
                    condition: "true",
                  })
                }
              >
                <Plus size={16} />
                New {entityNames[page]}
              </button>
            )}
            {page === "releases" && (
              <button
                className="primary"
                onClick={() =>
                  setEditor({ new: true, release: true, name: "" })
                }
              >
                <Plus size={16} />
                New release
              </button>
            )}
          </div>
        </div>
        {selected.size > 0 && (
          <div className="selection-bar">
            <strong>{selected.size} selected</strong>
            <button
              onClick={async () => {
                try {
                  await write(
                    "/" + page + "/batch/edit",
                    {
                      batch: {
                        ids: [...selected],
                        state: { state: "Retired" },
                      },
                    },
                    "PUT",
                  );
                  setSelected(new Set());
                  refresh();
                  notify("Selected records moved to Retired.");
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Move to Retired
            </button>
            <button onClick={() => setSelected(new Set())}>
              Clear selection
            </button>
          </div>
        )}
        {!data ? (
          <Loading />
        ) : !data.data?.length ? (
          <Empty text="No matching records." />
        ) : (
          <div className="table-scroll">
            <table id="records-table" className={wrap ? "wrap" : ""}>
              <thead>
                <tr>
                  {editable && (
                    <th className="checkbox-cell">
                      <input
                        aria-label="Select all visible records"
                        type="checkbox"
                        checked={
                          data.data.length > 0 &&
                          data.data.every((r: any) => selected.has(r.id))
                        }
                        onChange={(e) =>
                          setSelected(
                            e.target.checked
                              ? new Set(data.data.map((r: any) => r.id))
                              : new Set(),
                          )
                        }
                      />
                    </th>
                  )}
                  <th>
                    {editable
                      ? "Name / indicator"
                      : page === "jobs"
                        ? "Job"
                        : "Activity / release"}
                  </th>
                  <th>Status</th>
                  <th>{page === "yara_rules" ? "Category" : "Details"}</th>
                  {columns.map((c) => (
                    <th key={c.id}>{c.key}</th>
                  ))}
                  <th>Updated</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.data.map((row: any) => (
                  <tr key={row.id}>
                    {editable && (
                      <td className="checkbox-cell">
                        <input
                          type="checkbox"
                          aria-label={`Select ${row.name || row.ip || row.domain_name || row.title}`}
                          checked={selected.has(row.id)}
                          onChange={() => {
                            const next = new Set(selected);
                            next.has(row.id)
                              ? next.delete(row.id)
                              : next.add(row.id);
                            setSelected(next);
                          }}
                        />
                      </td>
                    )}
                    <td>
                      <button className="record-name" onClick={() => open(row)}>
                        <span className="file-icon">
                          {page === "c2ips" ? (
                            <Network size={17} />
                          ) : page === "c2dns" ? (
                            <Globe size={17} />
                          ) : (
                            <FileCode2 size={17} />
                          )}
                        </span>
                        <span>
                          {row.name ||
                            row.ip ||
                            row.domain_name ||
                            row.title ||
                            row.kind ||
                            row.activity_text ||
                            row.id}
                          <small>
                            {row.uuid
                              ? row.uuid
                              : row.created_user?.email ||
                                row.user?.email ||
                                row.id}
                          </small>
                        </span>
                      </button>
                    </td>
                    <td>
                      <Badge
                        value={
                          row.status ||
                          row.state ||
                          (page === "releases" ? "Released" : row.activity_type)
                        }
                      />
                    </td>
                    <td className="long-text">
                      {row.category ||
                        row.description ||
                        row.error ||
                        (row.progress != null
                          ? row.progress + "% complete"
                          : row.entity_type ||
                            fmt(row.num_signatures) + " signatures")}
                    </td>
                    {columns.map((c) => (
                      <td key={c.id}>
                        {row.metadata_values?.[c.key]?.value ?? "—"}
                      </td>
                    ))}
                    <td className="date-cell">
                      {date(
                        row.last_revision_date ||
                          row.date_modified ||
                          row.created_at ||
                          row.date_created ||
                          row.activity_date,
                      )}
                    </td>
                    <td>
                      <IconButton label="Open record" onClick={() => open(row)}>
                        <ArrowUpRight size={16} />
                      </IconButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && (
          <div className="pagination">
            <span>
              {fmt(data.total_count)} records{" "}
              <span className="muted">
                · {data.data?.length || 0} on this page
              </span>
            </span>
            <div>
              <IconButton
                label="Previous page"
                onClick={() => setIndex(Math.max(0, index - 1))}
              >
                <ChevronLeft size={17} />
              </IconButton>
              <span>Page {index + 1}</span>
              <button
                aria-label="Next page"
                className="icon-button"
                disabled={(index + 1) * 25 >= data.total_count}
                onClick={() => setIndex(index + 1)}
              >
                <ChevronRight size={17} />
              </button>
            </div>
          </div>
        )}
      </section>
      {editor && (
        <ArtifactEditor
          page={page}
          initial={editor}
          notify={notify}
          onClose={() => setEditor(null)}
          onSaved={() => {
            setEditor(null);
            refresh();
          }}
        />
      )}
      {extra && (
        <Dialog
          title={extra.kind || extra.name || "Activity details"}
          onClose={() => setExtra(null)}
        >
          <div className="dialog-body">
            <dl className="detail-list">
              {Object.entries(extra).map(([key, value]) => (
                <div key={key}>
                  <dt>{key.replaceAll("_", " ")}</dt>
                  <dd>
                    <pre>
                      {typeof value === "object"
                        ? JSON.stringify(value, null, 2)
                        : String(value ?? "—")}
                    </pre>
                  </dd>
                </div>
              ))}
            </dl>
            {page === "releases" && (
              <div className="button-row">
                <a
                  className="button primary"
                  href={base + "/releases/" + extra.id + "/artifact_export"}
                >
                  Download archive
                </a>
                <a
                  className="button"
                  href={base + "/releases/" + extra.id + "/release_notes"}
                >
                  Release notes
                </a>
              </div>
            )}
          </div>
        </Dialog>
      )}
    </>
  );
}
function ArtifactEditor({ page, initial, onClose, onSaved, notify }: any) {
  const [value, setValue] = useState<any>(initial),
    [tab, setTab] = useState("Content"),
    [states, setStates] = useState<any[]>([]),
    [definitions, setDefinitions] = useState<any[]>([]),
    [users, setUsers] = useState<any[]>([]),
    [busy, setBusy] = useState(false),
    [files, setFiles] = useState<any[]>(initial.files || []),
    [chosen, setChosen] = useState<Set<number>>(new Set()),
    [results, setResults] = useState<any>(null),
    [following, setFollowing] = useState(false);
  const isRule = page === "yara_rules",
    key = isRule
      ? "name"
      : page === "c2ips"
        ? "ip"
        : page === "c2dns"
          ? "domain_name"
          : page === "tasks"
            ? "title"
            : "name";
  useEffect(() => {
    if (!initial.new) {
      const type = ({ yara_rules: 1, c2dns: 2, c2ips: 3, tasks: 4 } as any)[
        page
      ];
      api("/bookmarks?entity_type=" + type + "&entity_id=" + initial.id).then(
        (r) => setFollowing(r.length > 0),
      );
    }
    const artifactType = (
      { yara_rules: 1, c2dns: 2, c2ips: 3, tasks: 4 } as any
    )[page];
    if (artifactType)
      api("/metadata?artifact_type=" + artifactType).then(setDefinitions);
    api("/cfg_states").then(setStates);
    api("/users").then((r) => setUsers(r.filter((u: any) => u.id)));
    if (isRule && !initial.new) {
      api("/yara_rules/" + initial.id + "/sample-results").then(setResults);
      api("/files?entity_type=1&entity_id=" + initial.id).then(setFiles);
    }
  }, []);
  const field = (name: string, v: any) =>
    setValue((x: any) => ({ ...x, [name]: v }));
  async function save(e: any) {
    e.preventDefault();
    setBusy(true);
    try {
      const payload = {
        ...value,
        state:
          typeof value.state === "object" ? value.state.state : value.state,
        category:
          typeof value.category === "object"
            ? value.category.category
            : value.category,
      };
      await write(
        "/" + page + (initial.new ? "" : "/" + initial.id),
        payload,
        initial.new ? "POST" : "PUT",
      );
      notify(initial.new ? "Record created." : "Changes saved.");
      onSaved();
    } catch (err: any) {
      notify(err.message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog
      wide
      title={
        initial.new
          ? "New " + (entityNames[page] || "release")
          : initial.name || initial.ip || initial.domain_name || initial.title
      }
      onClose={onClose}
    >
      <div className="tabs">
        {(isRule
          ? ["Content", "Revisions", "Samples & files"]
          : ["Content"]
        ).map((t) => (
          <button
            key={t}
            className={tab === t ? "active" : ""}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="dialog-body">
        {tab === "Content" ? (
          <form id="artifact-form" onSubmit={save}>
            <div className="form-grid">
              <label className="span2">
                {isRule
                  ? "Rule name"
                  : key === "ip"
                    ? "IP address"
                    : key === "domain_name"
                      ? "Domain name"
                      : "Name"}
                <input
                  required
                  value={value[key] || ""}
                  onChange={(e) => field(key, e.target.value)}
                />
              </label>
              {!initial.release && (
                <>
                  <label>
                    Workflow state
                    <select
                      required
                      value={
                        typeof value.state === "object"
                          ? value.state.state
                          : value.state || ""
                      }
                      onChange={(e) => field("state", e.target.value)}
                    >
                      <option value="">Choose a state</option>
                      {states.map((s) => (
                        <option key={s.id}>{s.state}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Owner
                    <select
                      value={value.owner_user?.id || value.owner_user_id || ""}
                      onChange={(e) =>
                        field(
                          "owner_user",
                          e.target.value
                            ? { id: Number(e.target.value) }
                            : null,
                        )
                      }
                    >
                      <option value="">Unassigned</option>
                      {users.map((u) => (
                        <option key={u.id} value={u.id}>
                          {u.email}
                        </option>
                      ))}
                    </select>
                  </label>
                  {isRule && (
                    <label className="span2">
                      Category
                      <input
                        value={
                          typeof value.category === "object"
                            ? value.category.category
                            : value.category || ""
                        }
                        onChange={(e) => field("category", e.target.value)}
                      />
                    </label>
                  )}
                  <label className="span2">
                    Description
                    <textarea
                      rows={3}
                      value={value.description || ""}
                      onChange={(e) => field("description", e.target.value)}
                    />
                  </label>
                  {isRule && (
                    <>
                      <label className="span2">
                        Strings
                        <textarea
                          className="code-input"
                          spellCheck={false}
                          rows={7}
                          value={value.strings || ""}
                          onChange={(e) => field("strings", e.target.value)}
                        />
                      </label>
                      <label className="span2">
                        Condition
                        <textarea
                          className="code-input"
                          spellCheck={false}
                          rows={4}
                          value={value.condition || ""}
                          onChange={(e) => field("condition", e.target.value)}
                        />
                      </label>
                      <label className="span2">
                        Imports
                        <textarea
                          className="code-input"
                          rows={2}
                          value={value.imports || ""}
                          onChange={(e) => field("imports", e.target.value)}
                        />
                      </label>
                    </>
                  )}
                  <label className="span2">
                    Tags <small>Separate with commas</small>
                    <input
                      value={(value.tags || [])
                        .map((t: any) => (typeof t === "string" ? t : t.text))
                        .join(", ")}
                      onChange={(e) =>
                        field(
                          "tags",
                          e.target.value
                            .split(",")
                            .map((t) => t.trim())
                            .filter(Boolean),
                        )
                      }
                    />
                  </label>
                  {definitions
                    .filter((d: any) => d.active)
                    .map((definition: any) => {
                      const item = value.metadata_values?.[definition.key];
                      const change = (v: any) =>
                        field("metadata_values", {
                          ...value.metadata_values,
                          [definition.key]: { ...item, value: v },
                        });
                      return (
                        <label key={definition.id}>
                          {definition.key}
                          {definition.choices?.length ? (
                            <select
                              value={item?.value ?? definition.default ?? ""}
                              onChange={(e) => change(e.target.value)}
                            >
                              <option value="">Choose a value</option>
                              {definition.choices.map((c: any) => (
                                <option key={c.id} value={c.choice}>
                                  {c.choice}
                                </option>
                              ))}
                            </select>
                          ) : (
                            <input
                              required={!!definition.required}
                              value={item?.value ?? definition.default ?? ""}
                              type={
                                definition.type === "number" ? "number" : "text"
                              }
                              onChange={(e) => change(e.target.value)}
                            />
                          )}
                        </label>
                      );
                    })}
                  <div className="span2">
                    {isRule && !initial.new && (
                      <ConfidenceSchedule ruleId={initial.id} notify={notify} />
                    )}
                  </div>
                  {!!initial.comments?.length && (
                    <section className="span2">
                      <h3>Review discussion</h3>
                      {initial.comments.map((comment: any) => (
                        <article className="review-comment" key={comment.id}>
                          <p>{comment.comment}</p>
                          <small>
                            {comment.user?.email} · {date(comment.date_created)}
                          </small>
                        </article>
                      ))}
                    </section>
                  )}
                  <label className="span2">
                    Draft comment <small>Saved with your changes</small>
                    <textarea
                      rows={3}
                      value={value.new_comment || ""}
                      onChange={(e) => field("new_comment", e.target.value)}
                      placeholder="Add review context…"
                    />
                  </label>
                </>
              )}
            </div>
          </form>
        ) : tab === "Revisions" ? (
          <div>
            {initial.revisions?.length ? (
              initial.revisions.map((r: any) => (
                <article className="activity-row" key={r.revision}>
                  <span className="event-icon">
                    <History size={17} />
                  </span>
                  <div>
                    <strong>Revision {r.revision}</strong>
                    <small>
                      {date(r.date_created)} · {r.user?.email}
                    </small>
                    <p>{r.releases || "Not included in a release"}</p>
                  </div>
                  <button
                    onClick={async () => {
                      try {
                        await write(
                          "/yara_rules/" +
                            initial.id +
                            "/revisions/" +
                            r.revision +
                            "/restore",
                          {},
                        );
                        notify("Revision restored as a new revision.");
                        onSaved();
                      } catch (e: any) {
                        notify(e.message, true);
                      }
                    }}
                  >
                    Restore
                  </button>
                </article>
              ))
            ) : (
              <Empty text="No revisions yet." />
            )}
          </div>
        ) : (
          <>
            <div className="section-top">
              <h3>Attached samples</h3>
              <label className="button">
                <Upload size={15} />
                Upload file
                <input
                  type="file"
                  hidden
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    const body = new FormData();
                    body.append("file", file);
                    body.append("entity_type", "1");
                    body.append("entity_id", initial.id);
                    try {
                      await api("/file_upload", { method: "POST", body });
                      setFiles(
                        await api(
                          "/files?entity_type=1&entity_id=" + initial.id,
                        ),
                      );
                      notify("Sample uploaded.");
                    } catch (err: any) {
                      notify(err.message, true);
                    }
                  }}
                />
              </label>
            </div>
            {files.map((file) => (
              <label className="file-row" key={file.id}>
                <input
                  type="checkbox"
                  aria-label={"Select file " + file.filename}
                  checked={chosen.has(file.id)}
                  onChange={() => {
                    setChosen((previous) => {
                      const next = new Set(previous);
                      next.has(file.id)
                        ? next.delete(file.id)
                        : next.add(file.id);
                      return next;
                    });
                  }}
                />
                <FileCode2 size={18} />
                <span>
                  {file.filename}
                  <small>{file.sha256 || file.sha1}</small>
                </span>
                <a
                  aria-label={"Download " + file.filename}
                  href={base + "/files/" + file.id}
                >
                  <Download size={16} />
                </a>
              </label>
            ))}
            {!files.length && <Empty text="No samples attached." />}
            <div className="button-row">
              <button
                disabled={!chosen.size}
                onClick={async () => {
                  try {
                    for (const id of chosen)
                      await api("/files/" + id, { method: "DELETE" });
                    setFiles(files.filter((f) => !chosen.has(f.id)));
                    setChosen(new Set());
                    notify("Selected files deleted.");
                  } catch (e: any) {
                    notify(e.message, true);
                  }
                }}
              >
                <Trash2 size={15} />
                Delete selected ({chosen.size})
              </button>
              <button
                onClick={async () => {
                  try {
                    const r = await write("/jobs", {
                      kind: "test_rule",
                      payload: { rule_id: initial.id, negative: false },
                    });
                    notify("Sample test queued: " + r.id.slice(0, 8));
                  } catch (e: any) {
                    notify(e.message, true);
                  }
                }}
              >
                <Play size={15} />
                Run sample test
              </button>
            </div>
            <button
              onClick={async () => {
                try {
                  const r = await write("/jobs", {
                    kind: "test_rule",
                    payload: { rule_id: initial.id, negative: true },
                  });
                  notify("Goodware test queued: " + r.id.slice(0, 8));
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Run goodware test
            </button>
            <div className="section-top">
              <h3>Match history</h3>
              <button
                onClick={async () =>
                  setResults(
                    await api("/yara_rules/" + initial.id + "/sample-results"),
                  )
                }
              >
                Refresh outcomes
              </button>
            </div>
            <label className="check-label">
              <input
                type="checkbox"
                onChange={async (e) =>
                  setResults(
                    await api(
                      "/yara_rules/" +
                        initial.id +
                        "/sample-results?show_all=" +
                        e.target.checked,
                    ),
                  )
                }
              />
              Include files that have never matched
            </label>
            {results?.files?.map((r: any) => (
              <article
                className={
                  "file-row " + (r.status === "regressed" ? "regressed" : "")
                }
                key={r.path}
              >
                <Badge value={r.status} />
                <span>
                  {r.path.split("/").pop()}
                  <small>{r.sha256}</small>
                </span>
              </article>
            ))}
          </>
        )}
      </div>
      <div className="dialog-footer">
        <span className="muted">
          {initial.uuid
            ? initial.uuid
            : initial.id
              ? "Record #" + initial.id
              : "Changes are validated before saving."}
        </span>
        <div className="button-row">
          {!initial.new && (
            <button
              onClick={async () => {
                try {
                  const type = { yara_rules: 1, c2dns: 2, c2ips: 3, tasks: 4 }[
                    page as "yara_rules"
                  ];
                  if (following)
                    await api(
                      "/bookmarks?entity_type=" +
                        type +
                        "&entity_id=" +
                        initial.id,
                      { method: "DELETE" },
                    );
                  else
                    await write("/bookmarks", {
                      entity_type: type,
                      entity_id: initial.id,
                    });
                  setFollowing(!following);
                  notify(
                    following ? "Stopped following." : "Following this record.",
                  );
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              <Bell size={16} />
              {following ? "Unfollow" : "Follow"}
            </button>
          )}
          {isRule && initial.active === false && (
            <button
              onClick={async () => {
                await write("/yara_rules/" + initial.id + "/restore", {});
                onSaved();
                notify("Signature restored.");
              }}
            >
              Restore signature
            </button>
          )}
          <button onClick={onClose}>Close</button>
          {tab === "Content" && (
            <button
              className="primary"
              type="submit"
              form="artifact-form"
              disabled={busy}
            >
              {busy ? (
                <Loader2 className="spin" size={16} />
              ) : (
                <Check size={16} />
              )}
              Save changes
            </button>
          )}
        </div>
      </div>
    </Dialog>
  );
}
function SampleLab({ notify }: any) {
  const [files, setFiles] = useState<File[]>([]),
    [result, setResult] = useState<any>(null),
    [name, setName] = useState("generated_candidate"),
    [busy, setBusy] = useState(false);
  async function run(generate = false) {
    if (!files.length) return;
    setBusy(true);
    try {
      const body = new FormData();
      if (generate) {
        files.forEach((f) => body.append("files", f));
        body.append("name", name);
      } else body.append("file", files[0]);
      setResult(
        await api(generate ? "/yara_rules/generate" : "/scan", {
          method: "POST",
          body,
        }),
      );
      notify(
        generate
          ? "Draft candidate generated and validated."
          : "Scan complete.",
      );
    } catch (e: any) {
      notify(e.message, true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="lab-grid">
      <section className="panel">
        <span className="eyebrow">LOCAL SAMPLE ANALYSIS</span>
        <h2>Make the next signal clearer.</h2>
        <p className="muted">
          Scan one sample against your active signatures, or use related samples
          to generate a draft.
        </p>
        <label className="dropzone">
          <Upload size={30} />
          <strong>Choose sample files</strong>
          <span>Files stay in the local analysis workflow.</span>
          <input
            type="file"
            multiple
            onChange={(e) => setFiles(Array.from(e.target.files || []))}
          />
        </label>
        {files.map((f) => (
          <div className="file-row" key={f.name}>
            <FileCode2 size={17} />
            <span>{f.name}</span>
            <small>{fmt(f.size)} bytes</small>
          </div>
        ))}
        <label>
          Candidate name
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <div className="button-row">
          <button
            className="primary"
            disabled={!files.length || busy}
            onClick={() => run()}
          >
            <ScanLine size={17} />
            Scan sample
          </button>
          <button disabled={!files.length || busy} onClick={() => run(true)}>
            <Plus size={17} />
            Generate candidate
          </button>
        </div>
      </section>
      <section className="panel">
        <div className="section-top">
          <h2>Analysis results</h2>
          {result && <Badge value="Complete" />}
        </div>
        {!result ? (
          <Empty text="Your results will appear here." />
        ) : result.source ? (
          <>
            <p>{result.review_note}</p>
            <pre className="source-preview">{result.source}</pre>
            <button
              className="primary"
              onClick={async () => {
                try {
                  await write("/import", {
                    import_text: result.source,
                    autocommit: true,
                    extract_ip: false,
                    extract_dns: false,
                    shared_state: "Vetting",
                    tags: ["source:generated"],
                  });
                  notify("Candidate imported into Vetting.");
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Import for review <ArrowUpRight size={16} />
            </button>
          </>
        ) : (
          <>
            <strong>{result.matches?.length || 0} signature matches</strong>
            {result.matches?.map((m: any) => (
              <article className="result-hit" key={m.rule}>
                <h3>{m.rule}</h3>
                {m.strings.map((s: any) => (
                  <p key={s.identifier}>
                    <code>{s.identifier}</code> · {s.instances.length}{" "}
                    occurrence(s)
                  </p>
                ))}
              </article>
            ))}
            {!result.matches?.length && (
              <p className="muted">No active signature matched this sample.</p>
            )}
          </>
        )}
      </section>
    </div>
  );
}
function Content({ version, notify, refresh }: any) {
  const [pack, setPack] = useState("sigpack"),
    [newName, setNewName] = useState<any>(null),
    [config, setConfig] = useState<any>(null),
    [data, setData] = useState<any>(null),
    [q, setQ] = useState(""),
    [group, setGroup] = useState("default"),
    [index, setIndex] = useState(0),
    [edit, setEdit] = useState<any>(null),
    [text, setText] = useState("");
  useEffect(() => {
    setIndex(0);
  }, [q, group]);
  useEffect(() => {
    api(
      "/content?" +
        new URLSearchParams({ q, group, offset: String(index * 25) }),
    )
      .then(setData)
      .catch((e: any) => notify(e.message, true));
  }, [version, q, group, index]);
  async function action(kind: string) {
    try {
      await write("/content/jobs", { kind, payload: { group, kind: pack } });
      notify("Content job queued. Follow its progress in Background jobs.");
    } catch (e: any) {
      notify(e.message, true);
    }
  }
  if (!data) return <Loading />;
  return (
    <>
      {newName !== null && (
        <Dialog
          title="New versioned signature"
          onClose={() => setNewName(null)}
        >
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                const value = await write("/content/rules", {
                  name: newName,
                  category: "UC",
                });
                setEdit(value);
                setText(value.yaml);
                setNewName(null);
                refresh();
              } catch (err: any) {
                notify(err.message, true);
              }
            }}
          >
            <div className="dialog-body">
              <label>
                Rule name
                <input
                  required
                  pattern="[A-Za-z_][A-Za-z0-9_]*"
                  autoFocus
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </label>
              <p className="muted">
                A stable UUID is assigned automatically. The rule starts as a
                draft.
              </p>
            </div>
            <div className="dialog-footer">
              <button type="button" onClick={() => setNewName(null)}>
                Cancel
              </button>
              <button className="primary">Create draft</button>
            </div>
          </form>
        </Dialog>
      )}
      {config && (
        <Dialog
          wide
          title="Repository settings"
          onClose={() => setConfig(null)}
        >
          <div className="dialog-body">
            <label>
              Content definition
              <select
                value={config.name}
                onChange={async (e) => {
                  const name = e.target.value;
                  const value = await api("/content/config/" + name);
                  setConfig({ name, yaml: value.yaml });
                }}
              >
                {[
                  "macros",
                  "categories",
                  "policies",
                  "pairings",
                  "collections",
                  "indicators",
                  "components",
                ].map((name) => (
                  <option key={name}>{name}</option>
                ))}
              </select>
            </label>
            <label>
              YAML definition
              <textarea
                className="code-input yaml-editor"
                value={config.yaml}
                onChange={(e) => setConfig({ ...config, yaml: e.target.value })}
              />
            </label>
          </div>
          <div className="dialog-footer">
            <button onClick={() => setConfig(null)}>Close</button>
            <button
              className="primary"
              onClick={async () => {
                try {
                  await write(
                    "/content/config/" + config.name,
                    { yaml: config.yaml },
                    "PUT",
                  );
                  notify("Repository definition committed.");
                  setConfig(null);
                  refresh();
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Validate & commit
            </button>
          </div>
        </Dialog>
      )}
      <div className="content-summary">
        <span>
          <GitBranch size={17} />
          <strong>{data.git_commit?.slice(0, 8)}</strong>
          <small>
            {data.git_status ? "Uncommitted changes" : "Working tree clean"}
          </small>
        </span>
        <span>{fmt(data.rule_count)} versioned signatures</span>
        <div className="button-row">
          <button onClick={() => setNewName("")}>
            <Plus size={16} />
            New signature
          </button>
          <button
            onClick={async () => {
              const value = await api("/content/config/macros");
              setConfig({ name: "macros", yaml: value.yaml });
            }}
          >
            Repository settings
          </button>
          <button onClick={() => action("validate_content")}>
            <CheckCircle2 size={16} />
            Validate content
          </button>
          <select
            aria-label="Content pack type"
            value={pack}
            onChange={(e) => setPack(e.target.value)}
          >
            <option value="sigpack">Sigpack</option>
            <option value="feedpack">Feedpack</option>
            <option value="codepack">Codepack</option>
          </select>
          <button className="primary" onClick={() => action("build_content")}>
            <Package size={16} />
            Build {pack}
          </button>
        </div>
      </div>
      <section className="panel records-panel">
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search YAML signatures"
              placeholder="Search versioned signatures…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <select
            aria-label="Policy group"
            value={group}
            onChange={(e) => setGroup(e.target.value)}
          >
            {Object.keys(data.groups).map((g) => (
              <option key={g}>{g}</option>
            ))}
          </select>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Signature</th>
                <th>Workflow</th>
                <th>Category</th>
                <th>Context tags</th>
                <th>Identity</th>
              </tr>
            </thead>
            <tbody>
              {data.data.map((r: any) => (
                <tr key={r.id}>
                  <td>
                    <button
                      className="record-name"
                      onClick={async () => {
                        const v = await api("/content/rules/" + r.id);
                        setEdit(v);
                        setText(v.yaml);
                      }}
                    >
                      <span className="file-icon">
                        <FileCode2 size={18} />
                      </span>
                      <span>
                        {r.name}
                        <small>{r.description}</small>
                      </span>
                    </button>
                  </td>
                  <td>
                    <Badge value={r.status} />
                  </td>
                  <td>{r.category}</td>
                  <td>
                    <div className="tag-list">
                      {r.tags?.slice(0, 2).map((t: string) => (
                        <span className="tag" key={t}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <code className="muted">{r.id.slice(0, 13)}…</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pagination">
          <span>{fmt(data.total_count)} signatures in this group</span>
          <div>
            <IconButton
              label="Previous content page"
              onClick={() => setIndex(Math.max(0, index - 1))}
            >
              <ChevronLeft size={16} />
            </IconButton>
            <span>Page {index + 1}</span>
            <button
              className="icon-button"
              aria-label="Next content page"
              disabled={(index + 1) * 25 >= data.total_count}
              onClick={() => setIndex(index + 1)}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </section>
      <div className="section-top standalone">
        <div>
          <h2>Builds & release gates</h2>
          <p className="muted">
            Review the exact source before publishing to testing. Production
            requires a clear telemetry window.
          </p>
        </div>
        <button
          onClick={async () => {
            try {
              await write("/content/review", {});
              notify("Independent review recorded.");
              refresh();
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          Record independent review
        </button>
      </div>
      <section className="panel">
        {!data.builds.length ? (
          <Empty text="No content builds yet." />
        ) : (
          data.builds.map((b: any) => (
            <article className="activity-row" key={b.id}>
              <span className="event-icon">
                <Package size={18} />
              </span>
              <div>
                <strong>
                  {b.kind} · {b.id.slice(0, 8)}
                </strong>
                <small>
                  {b.rules || b.indicators || b.components || 0} items ·{" "}
                  {b.group} · source {b.source_digest.slice(0, 10)}
                </small>
              </div>
              <a
                className="button"
                href={base + "/content/builds/" + b.id + "/download"}
              >
                <Download size={15} />
                Download
              </a>
              <button
                onClick={async () => {
                  try {
                    await write("/content/releases/" + b.id + "/testing", {});
                    notify("Published to the testing channel.");
                    refresh();
                  } catch (e: any) {
                    notify(e.message, true);
                  }
                }}
              >
                Publish to testing
              </button>
              <button
                onClick={async () => {
                  try {
                    await write("/content/releases/" + b.id + "/promote", {});
                    notify("Promoted to production.");
                    refresh();
                  } catch (e: any) {
                    notify(e.message, true);
                  }
                }}
              >
                Promote
              </button>
            </article>
          ))
        )}
      </section>
      {edit && (
        <Dialog wide title="Versioned signature" onClose={() => setEdit(null)}>
          <div className="dialog-body">
            <div className="banner">
              <GitBranch size={18} />
              <span>
                Saving validates the content and creates a Git commit. The UUID
                stays stable.
              </span>
            </div>
            <label>
              Signature YAML
              <textarea
                className="code-input yaml-editor"
                spellCheck={false}
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
            <h3>Git history</h3>
            {edit.history.map((h: string) => (
              <pre className="history-line" key={h}>
                {h}
              </pre>
            ))}
          </div>
          <div className="dialog-footer">
            <code>{edit.id}</code>
            <button
              className="primary"
              onClick={async () => {
                try {
                  await write(
                    "/content/rules/" + edit.id,
                    { yaml: text },
                    "PUT",
                  );
                  notify("Signature committed.");
                  setEdit(null);
                  refresh();
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              <Check size={16} />
              Validate & commit
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
function Configuration({ notify, refresh }: any) {
  const [tab, setTab] = useState("Metadata"),
    [data, setData] = useState<any[]>([]),
    [edit, setEdit] = useState<any>(null),
    [text, setText] = useState("");
  const paths: any = {
    Metadata: "metadata",
    Tags: "tags",
    Macros: "macros",
    Users: "users",
    Settings: "cfg_settings",
    Whitelist: "whitelist",
    Sources: "ingestion/health",
    States: "cfg_states",
    Categories: "cfg_category_range_mapping",
    Scripts: "scripts",
  };
  useEffect(() => {
    api("/" + paths[tab])
      .then((r) => setData(tab === "Sources" ? r.monitors : r))
      .catch((e: any) => notify(e.message, true));
  }, [tab]);
  return (
    <>
      <div className="tabs config-tabs">
        {Object.keys(paths).map((t) => (
          <button
            className={tab === t ? "active" : ""}
            key={t}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>
      <section className="panel">
        <div className="section-top">
          <div>
            <h2>{tab}</h2>
            <p className="muted">
              Manage workspace definitions and integrations.
            </p>
          </div>
          <button
            className="primary"
            onClick={() => {
              const template: any = {
                Metadata: {
                  key: "",
                  artifact_type: 1,
                  type: "string",
                  active: true,
                  choices: "",
                  show_in_table: 0,
                },
                Tags: { text: "" },
                Macros: { tag: "", value: "", description: "" },
                Users: { email: "", password: "", admin: false, active: true },
                Settings: { key: "", value: "", description: "", public: true },
                Whitelist: { whitelist_artifact: "", notes: "" },
                Sources: { name: "", max_delay_minutes: 60, enabled: true },
                States: {
                  state: "",
                  is_release_state: 0,
                  is_retired_state: 0,
                  is_staging_state: 0,
                },
                Categories: {
                  category: "",
                  range_min: 300000,
                  range_max: 399999,
                  include_in_release_notes: true,
                },
                Scripts: {
                  name: "",
                  description: "",
                  interpreter: "python3",
                  code: "",
                  match_regex: "",
                },
              };
              setEdit({ new: true });
              setText(JSON.stringify(template[tab], null, 2));
            }}
          >
            <Plus size={16} />
            Add {tab === "Sources" ? "source" : "definition"}
          </button>
        </div>
        {data.map((row: any, i) => (
          <button
            className="config-row"
            key={row.id || row.key || i}
            onClick={() => {
              setEdit(row);
              setText(
                JSON.stringify(
                  { ...row, choices: row.choices?.map((c: any) => c.choice) },
                  null,
                  2,
                ),
              );
            }}
          >
            <span className="event-icon">
              {tab === "Users" ? (
                <Users size={18} />
              ) : tab === "Tags" ? (
                <Tags size={18} />
              ) : (
                <Settings size={18} />
              )}
            </span>
            <div>
              <strong>
                {row.key ||
                  row.name ||
                  row.email ||
                  row.tag ||
                  row.text ||
                  row.whitelist_artifact}
              </strong>
              <small>
                {row.description ||
                  row.value ||
                  row.type ||
                  row.notes ||
                  row.last_success ||
                  "Workspace definition"}
              </small>
            </div>
            {row.stale && <Badge value="Stale" />}
            <ArrowUpRight size={16} />
          </button>
        ))}
        {!data.length && <Empty text="No definitions yet." />}
      </section>
      <section className="panel import-panel">
        <h2>Bring content into your workspace</h2>
        <p className="muted">
          Import YARA rules or indicators. Use retire mode to retire existing
          released indicators.
        </p>
        <ImportForm notify={notify} />
        <div className="button-row">
          <button
            onClick={async () => {
              try {
                const r = await write("/content/export-legacy", {});
                notify(
                  r.added + " signatures exported to the local Git repository.",
                );
              } catch (e: any) {
                notify(e.message, true);
              }
            }}
          >
            <GitBranch size={16} />
            Export legacy signatures to Git
          </button>
          <button
            onClick={async () => {
              try {
                const r = await write("/content/export-indicators", {});
                notify(
                  r.exported +
                    " reviewed indicators exported to Feedpack source.",
                );
              } catch (e: any) {
                notify(e.message, true);
              }
            }}
          >
            <GitBranch size={16} />
            Export released indicators to Git
          </button>
        </div>
      </section>
      {edit && (
        <Dialog
          title={edit.new ? "New definition" : "Edit definition"}
          onClose={() => setEdit(null)}
        >
          <div className="dialog-body">
            <p className="muted">
              Edit the definition fields below. Existing artifact values are
              validated before enum choices change.
            </p>
            <label>
              Definition JSON
              <textarea
                className="code-input"
                rows={18}
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
          </div>
          <div className="dialog-footer">
            <button onClick={() => setEdit(null)}>Cancel</button>
            <button
              className="primary"
              onClick={async () => {
                try {
                  const payload = JSON.parse(text);
                  let path = "/" + paths[tab];
                  if (tab === "Sources") path = "/ingestion/monitors";
                  else if (!edit.new)
                    path +=
                      "/" +
                      (edit.id || encodeURIComponent(edit.key || edit.tag));
                  await write(
                    path,
                    payload,
                    edit.new || tab === "Sources" ? "POST" : "PUT",
                  );
                  notify("Definition saved.");
                  setEdit(null);
                  api("/" + paths[tab]).then((r) =>
                    setData(tab === "Sources" ? r.monitors : r),
                  );
                  refresh();
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Save definition
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
function ImportForm({ notify }: any) {
  const [text, setText] = useState(""),
    [tags, setTags] = useState(""),
    [retire, setRetire] = useState(false),
    [result, setResult] = useState<any>(null);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        try {
          const r = await write("/import", {
            import_text: text,
            autocommit: true,
            retire_existing: retire,
            tags: tags
              .split(",")
              .map((t) => t.trim())
              .filter(Boolean),
          });
          setResult(r.artifacts);
          notify("Import processed. Review the result below.");
        } catch (err: any) {
          notify(err.message, true);
        }
      }}
    >
      <label>
        Rules or indicator text
        <textarea
          className="code-input"
          rows={6}
          value={text}
          onChange={(e) => setText(e.target.value)}
          required
        />
      </label>
      <div className="form-grid">
        <label>
          Context tags
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="source:community, campaign:example"
          />
        </label>
        <label className="check-label">
          <input
            type="checkbox"
            checked={retire}
            onChange={(e) => setRetire(e.target.checked)}
          />
          Retire matching released indicators
        </label>
      </div>
      <button className="primary">
        Process import <ArrowUpRight size={16} />
      </button>
      {result && (
        <pre className="source-preview">
          {JSON.stringify(
            {
              committed: result.committed?.length,
              retired: result.retired?.length,
              duplicates: result.duplicates?.length,
              errors: result.errors,
            },
            null,
            2,
          )}
        </pre>
      )}
    </form>
  );
}
function Following({ notify }: any) {
  const [items, setItems] = useState<any[]>([]);
  useEffect(() => {
    api("/bookmarks")
      .then(setItems)
      .catch((e: any) => notify(e.message, true));
  }, []);
  return (
    <section className="panel">
      {items.length ? (
        items.map((item) => (
          <article className="activity-row" key={item.id}>
            <Bell size={18} />
            <div>
              <strong>{item.artifact_name}</strong>
              <small>
                Updated {date(item.last_updated)}{" "}
                {item.revision ? " · Revision " + item.revision : ""}
              </small>
            </div>
            <a
              className="button"
              href={"#/" + item.permalink_prefix + "?id=" + item.entity_id}
            >
              Open record
            </a>
          </article>
        ))
      ) : (
        <Empty text="Follow records to keep track of their changes." />
      )}
    </section>
  );
}
function Account({ user, notify }: any) {
  const [keys, setKeys] = useState<any[]>([]),
    [secret, setSecret] = useState<any>(null),
    [password, setPassword] = useState("");
  const reload = () => api("/access_keys").then(setKeys);
  useEffect(() => {
    reload();
  }, []);
  return (
    <div className="split-panels">
      <section className="panel import-panel">
        <h2>Your profile</h2>
        <p>{user.email}</p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await write("/users/" + user.id, { ...user, password }, "PUT");
              setPassword("");
              notify("Password updated.");
            } catch (err: any) {
              notify(err.message, true);
            }
          }}
        >
          <label>
            New password
            <input
              type="password"
              autoComplete="new-password"
              minLength={8}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <button className="primary">Update password</button>
        </form>
      </section>
      <section className="panel import-panel">
        <h2>API access keys</h2>
        <p className="muted">
          Use a Bearer token with the X-ThreatKB-Secret header. Save a new
          secret before closing this view.
        </p>
        <button
          onClick={async () => {
            try {
              setSecret(await write("/access_keys", {}));
              reload();
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          Create access key
        </button>
        {secret && (
          <label>
            New secret (shown once)
            <textarea
              readOnly
              value={JSON.stringify(
                { token: secret.token, secret: secret.s_key },
                null,
                2,
              )}
            />
          </label>
        )}
        {keys.map((key) => (
          <article className="activity-row" key={key.id}>
            <div>
              <strong>Key #{key.id}</strong>
              <small>
                {date(key.created)} · {key.status}
              </small>
            </div>
            <button
              onClick={async () => {
                await write(
                  "/access_keys/" + key.id,
                  { status: key.status === "active" ? "inactive" : "active" },
                  "PUT",
                );
                reload();
              }}
            >
              {key.status === "active" ? "Disable" : "Enable"}
            </button>
            <button
              onClick={async () => {
                await write(
                  "/access_keys/" + key.id,
                  { status: "deleted" },
                  "PUT",
                );
                reload();
              }}
            >
              Revoke
            </button>
          </article>
        ))}
      </section>
    </div>
  );
}
function ConfidenceSchedule({ ruleId, notify }: any) {
  const [due, setDue] = useState(""),
    [confidence, setConfidence] = useState(90),
    [schedule, setSchedule] = useState<any>(null);
  useEffect(() => {
    api("/yara_rules/" + ruleId + "/confidence-schedule").then(setSchedule);
  }, [ruleId]);
  return (
    <fieldset className="schedule">
      <legend>Scheduled confidence change</legend>
      {schedule && (
        <p className="muted">
          Confidence {schedule.confidence} · {date(schedule.due_at)}{" "}
          {schedule.applied_at ? "· Applied" : "· Scheduled"}
        </p>
      )}
      <div className="form-grid">
        <label>
          Confidence
          <input
            type="number"
            min="0"
            max="100"
            value={confidence}
            onChange={(e) => setConfidence(Number(e.target.value))}
          />
        </label>
        <label>
          Apply on
          <input
            type="datetime-local"
            value={due}
            onChange={(e) => setDue(e.target.value)}
          />
        </label>
      </div>
      <div className="button-row">
        <button
          type="button"
          disabled={!due}
          onClick={async () => {
            try {
              setSchedule(
                await write(
                  "/yara_rules/" + ruleId + "/confidence-schedule",
                  { confidence, due_at: new Date(due).toISOString() },
                  "PUT",
                ),
              );
              notify("Confidence change scheduled.");
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          Schedule change
        </button>
        {schedule && !schedule.applied_at && (
          <button
            type="button"
            onClick={async () => {
              await api("/yara_rules/" + ruleId + "/confidence-schedule", {
                method: "DELETE",
              });
              setSchedule(null);
              notify("Scheduled change canceled.");
            }}
          >
            Cancel scheduled change
          </button>
        )}
      </div>
    </fieldset>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
