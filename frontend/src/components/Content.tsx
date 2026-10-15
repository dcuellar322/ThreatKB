import { useState, useEffect } from "react";
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
} from "lucide-react";
import { api, base, write } from "../lib/api";
import { fmt } from "../lib/format";

import { Badge, IconButton, Empty, Dialog, Loading } from "./ui";
export function Content({ version, notify, refresh }: any) {
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
    const controller = new AbortController();
    const timer = setTimeout(
      () =>
        api(
          "/content?" +
            new URLSearchParams({ q, group, offset: String(index * 25) }),
          { signal: controller.signal },
        )
          .then(setData)
          .catch((e: any) => {
            if (e.name !== "AbortError") notify(e.message, true);
          }),
      250,
    );
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
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
                  group,
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
                  aria-label="Rule name"
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
                aria-label="Content definition"
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
                aria-label="YAML definition"
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
          <button
            onClick={() => {
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
              setEdit(null);
              setNewName(null);
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
        <Dialog
          wide
          title="Versioned signature"
          dirty={text !== edit.yaml}
          onClose={() => setEdit(null)}
        >
          <div className="dialog-body">
            <label>
              Signature YAML
              <textarea
                aria-label="Signature YAML"
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
