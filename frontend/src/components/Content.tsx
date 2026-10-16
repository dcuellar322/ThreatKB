import { CodeEditor } from "./CodeEditor";
import { Select } from "./Select";
import { useState, useEffect, useRef } from "react";
import {
  FileCode2,
  Package,
  Search,
  Plus,
  ChevronLeft,
  ChevronRight,
  Check,
  GitBranch,
  Download,
  CheckCircle2,
  Loader2,
  AlertCircle,
} from "lucide-react";
import { api, base, write } from "../lib/api";
import { fmt } from "../lib/format";

import { Badge, IconButton, Empty, Dialog, Loading } from "./ui";
export function Content({ user, version, notify, refresh }: any) {
  const [pack, setPack] = useState("sigpack"),
    [newName, setNewName] = useState<any>(null),
    [busy, setBusy] = useState(false),
    [config, setConfig] = useState<any>(null),
    [data, setData] = useState<any>(null),
    [q, setQ] = useState(""),
    [query, setQuery] = useState(""),
    [group, setGroup] = useState("default"),
    [index, setIndex] = useState(0),
    [edit, setEdit] = useState<any>(null),
    [text, setText] = useState(""),
    [save, setSave] = useState<any>(null);
  const submitting = useRef(false);
  const storageKey = "threatkb:pending-content-save:" + user.id;
  const persist = (value: any) => {
    try {
      if (value) sessionStorage.setItem(storageKey, JSON.stringify(value));
      else sessionStorage.removeItem(storageKey);
    } catch {
      /* The job remains available in Background jobs if storage is full. */
    }
  };
  useEffect(() => {
    try {
      const pending = JSON.parse(sessionStorage.getItem(storageKey) || "null");
      if (pending?.job?.id) {
        setEdit(pending.edit);
        setConfig(pending.config);
        setNewName(pending.newName);
        setText(pending.text);
        setBusy(true);
        setSave(pending);
      }
    } catch {
      sessionStorage.removeItem(storageKey);
    }
  }, []);
  useEffect(() => {
    if (!save?.job || !["queued", "running"].includes(save.job.status)) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const job = await api("/jobs/" + save.job.id);
        if (cancelled) return;
        if (job.status === "succeeded") {
          persist(null);
          setBusy(false);
          setSave({
            job,
            message: "Committed · " + job.result.git_commit.slice(0, 8),
          });
          if (save.config)
            setConfig({
              ...save.config,
              ...job.result,
              original: job.result.yaml,
            });
          else {
            setNewName(null);
            setEdit(job.result);
            setText(job.result.yaml);
          }
          refresh();
        } else if (job.status === "failed") {
          persist(null);
          setBusy(false);
          setSave({
            job,
            error: job.error || "Save failed. Your draft is unchanged.",
          });
        } else {
          const pending = { ...save, job, error: null };
          persist(pending);
          setSave(pending);
        }
      } catch (error: any) {
        if (!cancelled)
          setSave({ ...save, error: "Unable to check save status. Retrying…" });
      }
      if (!cancelled) timer = setTimeout(poll, 1000);
    };
    timer = setTimeout(poll, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [save?.job?.id, save?.job?.status]);
  async function queueSave(path: string, payload: any, method = "PUT") {
    if (submitting.current || busy) return;
    submitting.current = true;
    setBusy(true);
    setSave(null);
    try {
      const job = await write(path, payload, method);
      const pending = { job, edit, config, newName, text };
      persist(pending);
      setSave(pending);
    } catch (error: any) {
      setSave({ error: error.message });
      setBusy(false);
    } finally {
      submitting.current = false;
    }
  }
  async function reloadSource() {
    if (busy || !confirm("Discard this draft and load the latest source?"))
      return;
    setBusy(true);
    try {
      const value = await api(
        config ? "/content/config/" + config.name : "/content/rules/" + edit.id,
      );
      if (config) setConfig({ ...config, ...value, original: value.yaml });
      else {
        setEdit(value);
        setText(value.yaml);
      }
      setSave(null);
    } catch (error: any) {
      setSave({ error: error.message });
    } finally {
      setBusy(false);
    }
  }
  const saveStatus = save && (
    <div
      className={"content-save-status" + (save.error ? " error" : "")}
      role={save.error ? "alert" : "status"}
    >
      {busy ? (
        <Loader2 size={16} className="spin" />
      ) : save.error ? (
        <AlertCircle size={16} />
      ) : (
        <Check size={16} />
      )}
      <span>
        {save.error ||
          save.message ||
          (save.job?.status === "running"
            ? "Validating in background…"
            : "Save queued…")}
      </span>
      {busy && save.job && (
        <button
          type="button"
          onClick={() => {
            setBusy(false);
            setSave(null);
            setEdit(null);
            setConfig(null);
            setNewName(null);
          }}
        >
          Continue in background
        </button>
      )}
      {!busy && save.error && (edit || config) && (
        <button type="button" onClick={reloadSource}>
          Reload latest
        </button>
      )}
    </div>
  );
  useEffect(() => {
    if (q === query) return;
    const timer = setTimeout(() => {
      setQuery(q);
      setIndex(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [q, query]);
  useEffect(() => {
    const controller = new AbortController();
    api(
      "/content?" +
        new URLSearchParams({ q: query, group, offset: String(index * 25) }),
      { signal: controller.signal },
    )
      .then(setData)
      .catch((e: any) => {
        if (e.name !== "AbortError") notify(e.message, true);
      });
    return () => {
      controller.abort();
    };
  }, [version, query, group, index]);
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
          dirty={!!newName}
          busy={busy}
          onClose={() => setNewName(null)}
        >
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              await queueSave(
                "/content/rules",
                {
                  name: newName,
                  category: "UC",
                  group,
                  revision: data.revision,
                },
                "POST",
              );
            }}
          >
            <div className="dialog-body">
              <label>
                Rule name
                <input
                  aria-label="Rule name"
                  required
                  disabled={busy}
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
            {saveStatus}
            <div className="dialog-footer">
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  if (!newName || confirm("Discard unsaved changes?"))
                    setNewName(null);
                }}
              >
                Cancel
              </button>
              <button className="primary" disabled={busy}>
                {busy ? "Creating…" : "Create draft"}
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {config && (
        <Dialog
          wide
          title="Repository settings"
          dirty={config.yaml !== config.original}
          busy={busy}
          onClose={() => setConfig(null)}
        >
          <div className="dialog-body">
            <label>
              Content definition
              <Select
                disabled={busy}
                aria-label="Content definition"
                value={config.name}
                onChange={async (e) => {
                  if (
                    config.yaml !== config.original &&
                    !confirm("Discard unsaved changes?")
                  )
                    return;
                  const name = e.target.value;
                  setBusy(true);
                  try {
                    const value = await api("/content/config/" + name);
                    setSave(null);
                    setConfig({ name, ...value, original: value.yaml });
                  } catch (e: any) {
                    notify(e.message, true);
                  } finally {
                    setBusy(false);
                  }
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
              </Select>
            </label>
            <div className="field ">
              <span>YAML definition</span>
              <CodeEditor
                mode="yaml"
                label="YAML definition"
                className="code-input yaml-editor"
                value={config.yaml}
                readOnly={busy}
                onChange={(e) => setConfig({ ...config, yaml: e.target.value })}
              />
            </div>
          </div>
          {saveStatus}
          <div className="dialog-footer">
            <button
              disabled={busy}
              onClick={() => {
                if (
                  config.yaml === config.original ||
                  confirm("Discard unsaved changes?")
                )
                  setConfig(null);
              }}
            >
              Close
            </button>
            <button
              className="primary"
              disabled={busy || config.yaml === config.original}
              onClick={async () => {
                await queueSave("/content/config/" + config.name, {
                  yaml: config.yaml,
                  revision: config.revision,
                });
              }}
            >
              {busy
                ? save?.job?.status === "running"
                  ? "Validating…"
                  : "Queued…"
                : "Validate & commit"}
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
          <button
            onClick={() => {
              setSave(null);
              setEdit(null);
              setConfig(null);
              setNewName("");
            }}
          >
            <Plus size={16} />
            New signature
          </button>
          <button
            onClick={async () => {
              setSave(null);
              setEdit(null);
              setNewName(null);
              try {
                const value = await api("/content/config/macros");
                setConfig({ name: "macros", ...value, original: value.yaml });
              } catch (error: any) {
                notify(error.message, true);
              }
            }}
          >
            Repository settings
          </button>
          <button onClick={() => action("validate_content")}>
            <CheckCircle2 size={16} />
            Validate content
          </button>
          <Select
            aria-label="Content pack type"
            value={pack}
            onChange={(e) => setPack(e.target.value)}
          >
            <option value="sigpack">Sigpack</option>
            <option value="feedpack">Feedpack</option>
            <option value="codepack">Codepack</option>
          </Select>
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
          <Select
            aria-label="Policy group"
            value={group}
            onChange={(e) => {
              setGroup(e.target.value);
              setIndex(0);
            }}
          >
            {Object.keys(data.groups).map((g) => (
              <option key={g}>{g}</option>
            ))}
          </Select>
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
                        try {
                          const v = await api("/content/rules/" + r.id);
                          setSave(null);
                          setEdit(v);
                          setText(v.yaml);
                        } catch (error: any) {
                          notify(error.message, true);
                        }
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
              disabled={!index}
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
      {!!data.channels.length && (
        <section className="panel" aria-label="Content release channels">
          {data.channels.map((release: any) => (
            <article
              className="activity-row content-channel-row"
              key={release.status + release.manifest.id}
            >
              <div>
                <strong>
                  {release.manifest.kind} · {release.manifest.group}
                </strong>
                <small>
                  {release.promotion_block?.message ||
                    release.manifest.id.slice(0, 8)}
                </small>
              </div>
              <Badge
                value={
                  release.promotion_block?.alarm ? "Alarm" : release.status
                }
              />
            </article>
          ))}
        </section>
      )}
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
        <Dialog
          wide
          title="Versioned signature"
          dirty={text !== edit.yaml}
          busy={busy}
          onClose={() => setEdit(null)}
        >
          <div className="dialog-body">
            <div className="field ">
              <span>Signature YAML</span>
              <CodeEditor
                mode="yaml"
                label="Signature YAML"
                className="code-input yaml-editor"
                spellCheck={false}
                value={text}
                readOnly={busy}
                onChange={(e) => setText(e.target.value)}
              />
            </div>
            <h3>Git history</h3>
            {edit.history.map((h: string) => (
              <pre className="history-line" key={h}>
                {h}
              </pre>
            ))}
          </div>
          {saveStatus}
          <div className="dialog-footer">
            <code>{edit.id}</code>
            <button
              disabled={busy}
              onClick={() => {
                if (text === edit.yaml || confirm("Discard unsaved changes?"))
                  setEdit(null);
              }}
            >
              Close
            </button>
            <button
              className="primary"
              disabled={busy || text === edit.yaml}
              onClick={async () => {
                await queueSave("/content/rules/" + edit.id, {
                  yaml: text,
                  revision: edit.revision,
                  file_name: edit.file_name,
                });
              }}
            >
              <Check size={16} />
              {busy
                ? save?.job?.status === "running"
                  ? "Validating…"
                  : "Queued…"
                : "Validate & commit"}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
