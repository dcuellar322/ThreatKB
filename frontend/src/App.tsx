import { normalizeHash } from "./lib/links";
import { useState, useEffect, useCallback, useRef } from "react";
import { Shield, Bell, Menu, LogOut, RefreshCw, X, Search } from "lucide-react";
import { api, write } from "./lib/api";
import { nav, title } from "./lib/navigation";
import { date } from "./lib/format";
import { IconButton, Dialog, Empty } from "./components/ui";
import { Login } from "./components/Login";
import { Dashboard } from "./components/Dashboard";
import { Records } from "./components/Records";
import { Content } from "./components/Content";
import { SampleLab } from "./components/SampleLab";
import { LegacyTools } from "./components/LegacyTools";
import {
  Configuration,
  ImportForm,
  GitExports,
} from "./components/Configuration";
import { Account, Following } from "./components/Account";

export function App() {
  const [user, setUser] = useState<any>(undefined),
    [route, setRoute] = useState(() => normalizeHash(location.hash)),
    [notice, setNotice] = useState<any>(null),
    [mobile, setMobile] = useState(false),
    [narrow, setNarrow] = useState(matchMedia("(max-width:800px)").matches),
    [notifications, setNotifications] = useState<any>(null),
    [unread, setUnread] = useState(0),
    [version, setVersion] = useState(0),
    [searchOpen, setSearchOpen] = useState(false),
    [search, setSearch] = useState(""),
    [hits, setHits] = useState<any>(null),
    [searchError, setSearchError] = useState("");
  const currentRoute = useRef(route);
  currentRoute.current = route;
  const page = route.replace(/^#!?\//, "").split("?")[0] || "yara_rules";
  const noticeTimer = useRef<ReturnType<typeof setTimeout> | undefined>(
    undefined,
  );
  const notify = useCallback((message: string, error = false) => {
    clearTimeout(noticeTimer.current);
    setNotice({ message, error });
    if (!error) noticeTimer.current = setTimeout(() => setNotice(null), 5000);
  }, []);
  const go = (next: string) => {
    const target = normalizeHash("#/" + next);
    if (
      target !== currentRoute.current &&
      !window.dispatchEvent(
        new Event("threatkb:before-navigate", { cancelable: true }),
      )
    )
      return;
    currentRoute.current = target;
    setRoute(target);
    location.hash = target;
    setMobile(false);
  };
  const refresh = () => setVersion((v) => v + 1);
  useEffect(() => {
    api("/users/me")
      .then(setUser)
      .catch(() => {
        sessionStorage.setItem("threatkb.returnTo", location.hash);
        setUser(null);
      });
    const hash = () => {
        if (location.hash === "#main-content") {
          document.getElementById("main-content")?.focus();
          return;
        }
        const next = normalizeHash(location.hash);
        if (
          next !== currentRoute.current &&
          !window.dispatchEvent(
            new Event("threatkb:before-navigate", { cancelable: true }),
          )
        ) {
          history.replaceState(null, "", currentRoute.current);
          return;
        }
        if (next !== location.hash) history.replaceState(null, "", next);
        setRoute(next);
      },
      expired = () => {
        sessionStorage.setItem("threatkb.returnTo", location.hash);
        setUser(null);
      };
    hash();
    window.addEventListener("hashchange", hash);
    window.addEventListener("threatkb:unauthorized", expired);
    return () => {
      window.removeEventListener("hashchange", hash);
      window.removeEventListener("threatkb:unauthorized", expired);
    };
  }, []);
  useEffect(() => {
    const media = matchMedia("(max-width:800px)");
    const changed = () => setNarrow(media.matches);
    media.addEventListener("change", changed);
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobile(false);
    };
    window.addEventListener("keydown", key);
    return () => {
      media.removeEventListener("change", changed);
      window.removeEventListener("keydown", key);
    };
  }, []);
  useEffect(() => {
    if (!user) return;
    const poll = () =>
      api("/notifications?summary=true")
        .then((r) => setUnread(r.unread_count))
        .catch(() => {});
    poll();
    const timer = setInterval(poll, 60000);
    return () => clearInterval(timer);
  }, [user, version]);
  useEffect(() => {
    if (!searchOpen || search.trim().length < 2) {
      setHits(null);
      return;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setSearchError("");
      api("/search?all=" + encodeURIComponent(search.trim()) + "&limit=8", {
        signal: controller.signal,
      })
        .then(setHits)
        .catch((e) => {
          if (e.name !== "AbortError") setSearchError(e.message);
        });
    }, 250);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [searchOpen, search]);
  const toast = notice && (
    <div className={"toast " + (notice.error ? "error" : "")} role="alert">
      <span>{notice.message}</span>
      <IconButton label="Dismiss notification" onClick={() => setNotice(null)}>
        <X size={16} />
      </IconButton>
    </div>
  );
  if (user === undefined) return <div className="boot">Loading ThreatKB…</div>;
  if (!user)
    return (
      <>
        <Login
          notify={notify}
          onLogin={(value: any) => {
            setUser(value);
            setNotice(null);
            const saved = sessionStorage.getItem("threatkb.returnTo");
            sessionStorage.removeItem("threatkb.returnTo");
            go(saved ? normalizeHash(saved).slice(2) : "yara_rules");
          }}
        />
        {toast}
      </>
    );
  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main-content")?.focus();
        }}
      >
        Skip to content
      </a>
      <aside
        inert={narrow && !mobile}
        className={"sidebar " + (mobile ? "visible" : "")}
      >
        <button className="brand" onClick={() => go("yara_rules")}>
          <Shield size={23} />
          <strong>
            Threat<span>KB</span>
          </strong>
        </button>
        <nav aria-label="Main navigation">
          {nav
            .filter(
              ([key]) =>
                user.admin || !["settings", "releases", "errors"].includes(key),
            )
            .map(([key, label, Icon]) => (
              <a
                href={"#/" + key}
                key={key}
                className={
                  (page === key ? "active " : "") +
                  (["yara_rules", "releases", "settings", "bookmarks"].includes(
                    key,
                  )
                    ? "nav-group-start"
                    : "")
                }
                aria-current={page === key ? "page" : undefined}
                onClick={() => setMobile(false)}
              >
                <Icon size={17} />
                <span>{label}</span>
              </a>
            ))}
        </nav>
        <div className="account-row">
          <button className="account" onClick={() => go("account")}>
            <strong>{user.first_name || user.email.split("@")[0]}</strong>
            <small>{user.admin ? "Administrator" : "Analyst"}</small>
          </button>
          <IconButton
            label="Sign out"
            onClick={async () => {
              await api("/logout");
              setUser(null);
              setNotice(null);
            }}
          >
            <LogOut size={17} />
          </IconButton>
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
          <IconButton
            label="Open navigation"
            aria-expanded={mobile}
            onClick={() => setMobile(!mobile)}
          >
            <Menu size={20} />
          </IconButton>
          <span className="topbar-title">ThreatKB</span>
          <div className="topbar-right">
            <button
              className="global-search"
              onClick={() => setSearchOpen(true)}
            >
              <Search size={15} />
              <span>Search all records</span>
            </button>
            <IconButton
              label={"Notifications (" + unread + " unread)"}
              onClick={async () => {
                try {
                  setNotifications(await api("/notifications"));
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              <Bell size={18} />
              {unread > 0 && (
                <span className="notification-count">{unread}</span>
              )}
            </IconButton>
          </div>
        </header>
        <main id="main-content" className="main" tabIndex={-1}>
          <div className="page-heading">
            <h1>{title(page)}</h1>
            {!["scanner", "import"].includes(page) && (
              <IconButton label="Refresh view" onClick={refresh}>
                <RefreshCw size={17} />
              </IconButton>
            )}
          </div>
          <section key={page} className="page-content">
            {page === "dashboard" ? (
              <Dashboard version={version} go={go} />
            ) : page === "content" ? (
              <Content version={version} notify={notify} refresh={refresh} />
            ) : page === "scanner" ? (
              <SampleLab notify={notify} />
            ) : page === "settings" ? (
              <Configuration
                version={version}
                notify={notify}
                refresh={refresh}
                selectedTab={new URLSearchParams(route.split("?")[1]).get(
                  "tab",
                )}
              />
            ) : page === "whitelist" ? (
              <Configuration
                version={version}
                notify={notify}
                refresh={refresh}
                selectedTab="Whitelist"
                standalone
              />
            ) : page === "import" ? (
              <section className="panel import-panel">
                <ImportForm notify={notify} />
                {user.admin && <GitExports notify={notify} />}
              </section>
            ) : ["tests", "files", "errors"].includes(page) ? (
              <LegacyTools
                page={page}
                version={version}
                notify={notify}
                user={user}
              />
            ) : page === "account" ? (
              <Account
                user={user}
                notify={notify}
                onUser={setUser}
                version={version}
              />
            ) : page === "bookmarks" ? (
              <Following notify={notify} version={version} />
            ) : (
              <Records
                page={page}
                version={version}
                notify={notify}
                refresh={refresh}
                user={user}
                navigate={go}
              />
            )}
          </section>
        </main>
      </div>
      {toast}
      {searchOpen && (
        <Dialog title="Search all records" onClose={() => setSearchOpen(false)}>
          <div className="dialog-body">
            <label>
              Search
              <input
                aria-label="Search all records"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                autoFocus
              />
            </label>
            {searchError && <p role="alert">{searchError}</p>}
            {hits &&
              [
                ["signatures", "yara_rules"],
                ["ips", "c2ips"],
                ["dns", "c2dns"],
                ["tasks", "tasks"],
              ].map(
                ([key, path]) =>
                  hits[key]?.length > 0 && (
                    <section key={key} className="search-results">
                      <h3>
                        {key === "ips"
                          ? "IP indicators"
                          : key === "dns"
                            ? "Domain indicators"
                            : key === "tasks"
                              ? "Review tasks"
                              : "Signatures"}
                      </h3>
                      {hits[key].map((row: any) => (
                        <button
                          key={row.id}
                          onClick={() => {
                            setSearchOpen(false);
                            go(path + "?id=" + row.id);
                          }}
                        >
                          {row.name || row.ip || row.domain_name || row.title}
                          <small>{row.state}</small>
                        </button>
                      ))}
                    </section>
                  ),
              )}
            {hits &&
              ["signatures", "ips", "dns", "tasks"].every(
                (key) => !hits[key]?.length,
              ) && <Empty text="No matching records." />}
          </div>
        </Dialog>
      )}
      {notifications && (
        <Dialog title="Notifications" onClose={() => setNotifications(null)}>
          <div className="dialog-body">
            <div className="section-top">
              <span>{notifications.unread_count} unread</span>
              <button
                onClick={async () => {
                  await write("/notifications/clear", {});
                  setNotifications((current: any) =>
                    current ? { data: [], unread_count: 0 } : null,
                  );
                  setUnread(0);
                }}
              >
                Clear notifications
              </button>
            </div>
            {notifications.data.length ? (
              notifications.data.map((item: any) => (
                <article className="activity-row" key={item.id}>
                  <div>
                    <strong>{item.activity_text}</strong>
                    <small>
                      {item.user?.email || "System"} ·{" "}
                      {date(item.activity_date)}
                    </small>
                  </div>
                </article>
              ))
            ) : (
              <Empty text="No unread notifications." />
            )}
          </div>
        </Dialog>
      )}
    </div>
  );
}
