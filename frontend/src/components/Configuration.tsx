import { useState, useEffect } from "react";
import { Plus, ArrowUpRight } from "lucide-react";
import { api, write } from "../lib/api";

import { Badge, Empty, Dialog } from "./ui";
const schemas: Record<string, Record<string, any>> = {
  Metadata: {
    key: "text",
    artifact_type: ["Signature|1", "Domain|2", "IP|3", "Task|4"],
    type: ["string", "integer", "date", "multiline_comment", "select"],
    default: "text",
    choices: "text",
    active: "check",
    required: "check",
    show_in_table: "check",
    export_with_release: "check",
  },
  Tags: { text: "text" },
  Macros: { tag: "text", value: "code", active: "check" },
  Users: {
    email: "email",
    first_name: "text",
    last_name: "text",
    password: "password",
    admin: "check",
    active: "check",
  },
  Settings: {
    key: "text",
    value: "text",
    description: "text",
    public: "check",
  },
  Whitelist: { whitelist_artifact: "text", notes: "textarea" },
  Sources: { name: "text", max_delay_minutes: "number", enabled: "check" },
  States: {
    state: "text",
    is_release_state: "check",
    is_staging_state: "check",
    is_retired_state: "check",
  },
  Categories: {
    category: "text",
    range_min: "number",
    range_max: "number",
    include_in_release_notes: "check",
  },
  Scripts: {
    name: "text",
    description: "text",
    interpreter: "text",
    code: "code",
    match_regex: "text",
  },
};
const labels: Record<string, string> = {
  artifact_type: "Artifact type",
  type: "Value type",
  key: "Key",
  show_in_table: "Show in table",
  export_with_release: "Include in exports",
  is_release_state: "Release state",
  is_staging_state: "Staging state",
  is_retired_state: "Retired state",
  range_min: "First Event ID",
  range_max: "Last Event ID",
  include_in_release_notes: "Include in release notes",
  max_delay_minutes: "Maximum delay (minutes)",
  whitelist_artifact: "Indicator",
  match_regex: "Highlight pattern",
};
export function Configuration({ notify, refresh }: any) {
  const [tab, setTab] = useState("Metadata"),
    [data, setData] = useState<any[]>([]),
    [edit, setEdit] = useState<any>(null),
    [value, setValue] = useState<any>({}),
    [q, setQ] = useState(""),
    [busy, setBusy] = useState(false),
    [run, setRun] = useState<any>(null),
    [args, setArgs] = useState(""),
    [output, setOutput] = useState<any>(null);
  const paths: any = {
    Metadata: "metadata?active_only=false",
    Tags: "tags",
    Macros: "macros?view=All",
    Users: "users?include_inactive=true",
    Settings: "cfg_settings?include_private=true",
    Whitelist: "whitelist",
    Sources: "ingestion/health",
    States: "cfg_states?counts=false",
    Categories: "cfg_category_range_mapping",
    Scripts: "scripts",
  };
  const reload = () =>
    api("/" + paths[tab])
      .then((r) =>
        setData(
          tab === "Sources"
            ? r.monitors
            : tab === "Users"
              ? r.filter((row: any) => row.id)
              : r,
        ),
      )
      .catch((e) => notify(e.message, true));
  useEffect(() => {
    setData([]);
    setQ("");
    reload();
  }, [tab]);
  const endpoint = () =>
    "/" +
    (tab === "Sources" ? "ingestion/monitors" : paths[tab].split("?")[0]) +
    (!edit.new && tab !== "Sources"
      ? "/" + encodeURIComponent(edit.id ?? edit.key ?? edit.tag)
      : "");
  const dirty = edit && JSON.stringify(value) !== JSON.stringify(edit.form);
  const close = () => {
    if (!busy && (!dirty || confirm("Discard unsaved changes?"))) setEdit(null);
  };
  const open = (row: any) => {
    const form = {
      ...row,
      choices: row.choices?.map((c: any) => c.choice).join(", ") ?? "",
      ...(tab === "Users" ? { password: "" } : {}),
    };
    setValue(form);
    setEdit({ ...row, form });
  };
  const add = () => {
    const defaults: any = {
      Metadata: {
        type: "string",
        artifact_type: 1,
        active: true,
        export_with_release: true,
      },
      Macros: { active: true },
      Users: { active: true, admin: false },
      Settings: { public: false },
      Sources: { max_delay_minutes: 60, enabled: true },
      Categories: {
        range_min: 300000,
        range_max: 399999,
        include_in_release_notes: true,
      },
      Scripts: { interpreter: "python3" },
    };
    open({ new: true, ...defaults[tab] });
  };
  const save = async (e: any) => {
    e.preventDefault();
    setBusy(true);
    try {
      const payload = { ...value };
      delete payload.new;
      if (tab === "Users" && !edit.new && !payload.password)
        delete payload.password;
      await write(
        endpoint(),
        payload,
        edit.new || tab === "Sources" ? "POST" : "PUT",
      );
      notify("Saved.");
      setEdit(null);
      reload();
      refresh();
    } catch (error: any) {
      notify(error.message, true);
    } finally {
      setBusy(false);
    }
  };
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
          <h2>{tab}</h2>
          <div className="button-row">
            <input
              aria-label="Search definitions"
              placeholder="Filter definitions"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <button className="primary" onClick={add}>
              <Plus size={15} />
              Add{" "}
              {tab === "Sources"
                ? "source"
                : tab === "Users"
                  ? "user"
                  : "definition"}
            </button>
          </div>
        </div>
        {data
          .filter((r) =>
            Object.values(r)
              .filter((v) => typeof v === "string" || typeof v === "number")
              .join(" ")
              .toLowerCase()
              .includes(q.toLowerCase()),
          )
          .map((row, i) => (
            <div className="config-row" key={row.id ?? row.key ?? row.tag ?? i}>
              <button className="config-open" onClick={() => open(row)}>
                <strong>
                  {row.key ||
                    row.name ||
                    row.email ||
                    row.tag ||
                    row.text ||
                    row.state ||
                    row.category ||
                    row.whitelist_artifact}
                </strong>
                <small>
                  {row.description ||
                    row.type ||
                    row.notes ||
                    row.last_success ||
                    ""}
                </small>
              </button>
              {row.stale && <Badge value="Stale" />}
              {tab === "Scripts" && (
                <button
                  onClick={() => {
                    setRun(row);
                    setArgs("");
                    setOutput(null);
                  }}
                >
                  Run
                </button>
              )}
              <button onClick={() => open(row)}>Edit</button>
            </div>
          ))}
        {!data.length && <Empty text="No definitions." />}
      </section>
      <details className="panel import-panel">
        <summary>Import and export</summary>
        <ImportForm notify={notify} />
        <div className="button-row">
          {[
            ["export-legacy", "Export signatures to Git"],
            ["export-indicators", "Export released indicators to Git"],
          ].map(([path, label]) => (
            <button
              key={path}
              onClick={async () => {
                try {
                  const r = await write("/content/" + path, {});
                  notify((r.added ?? r.exported) + " records exported.");
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              {label}
            </button>
          ))}
        </div>
      </details>
      {edit && (
        <Dialog
          title={
            (edit.new ? "Add " : "Edit ") +
            (tab === "Users"
              ? "user"
              : tab === "Sources"
                ? "source"
                : "definition")
          }
          onClose={() => setEdit(null)}
          dirty={dirty}
          busy={busy}
          wide={tab === "Scripts"}
        >
          <form onSubmit={save}>
            <div className="dialog-body form-grid">
              {Object.entries(schemas[tab]).map(([key, type]) => {
                const label =
                  labels[key] ||
                  key
                    .replaceAll("_", " ")
                    .replace(/^./, (s) => s.toUpperCase());
                const input = {
                  "aria-label": label,
                  id: "config-" + key,
                  value: value[key] ?? "",
                  onChange: (e: any) =>
                    setValue({
                      ...value,
                      [key]:
                        type === "number"
                          ? Number(e.target.value)
                          : e.target.value,
                    }),
                };
                return (
                  <label
                    key={key}
                    className={
                      type === "check"
                        ? "check-label"
                        : type === "code" || type === "textarea"
                          ? "span-two"
                          : ""
                    }
                  >
                    {type === "check" ? (
                      <>
                        <input
                          type="checkbox"
                          checked={!!value[key]}
                          onChange={(e) =>
                            setValue({ ...value, [key]: e.target.checked })
                          }
                        />
                        {label}
                      </>
                    ) : (
                      <>
                        {label}
                        {Array.isArray(type) ? (
                          <select {...input}>
                            {type.map((option) => {
                              const [text, val] = option.split("|");
                              return (
                                <option key={option} value={val ?? text}>
                                  {text}
                                </option>
                              );
                            })}
                          </select>
                        ) : type === "code" || type === "textarea" ? (
                          <textarea
                            {...input}
                            rows={type === "code" ? 12 : 3}
                            className={type === "code" ? "code-input" : ""}
                          />
                        ) : (
                          <input
                            {...input}
                            type={type}
                            required={
                              [
                                "key",
                                "tag",
                                "name",
                                "email",
                                "state",
                                "category",
                                "whitelist_artifact",
                              ].includes(key) ||
                              (key === "password" && edit.new)
                            }
                            autoComplete={
                              type === "password" ? "new-password" : undefined
                            }
                            readOnly={!edit.new && ["key", "tag"].includes(key)}
                          />
                        )}
                      </>
                    )}
                  </label>
                );
              })}
            </div>
            <div className="dialog-footer">
              {!edit.new && tab !== "Sources" && (
                <button
                  type="button"
                  className="text-danger"
                  onClick={async () => {
                    if (!confirm("Delete this definition?")) return;
                    try {
                      await api(endpoint(), { method: "DELETE" });
                      setEdit(null);
                      reload();
                      refresh();
                      notify("Deleted.");
                    } catch (e: any) {
                      notify(e.message, true);
                    }
                  }}
                >
                  Delete
                </button>
              )}
              <button type="button" onClick={close}>
                Cancel
              </button>
              <button className="primary" disabled={busy}>
                {busy ? "Saving…" : "Save"}
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {run && (
        <Dialog title={"Run " + run.name} onClose={() => setRun(null)}>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                setOutput(
                  await write("/scripts/run/" + run.id, { arguments: args }),
                );
              } catch (e: any) {
                notify(e.message, true);
              }
            }}
          >
            <div className="dialog-body">
              <label>
                Arguments
                <input
                  aria-label="Arguments"
                  value={args}
                  onChange={(e) => setArgs(e.target.value)}
                />
              </label>
              {output && (
                <pre className="source-preview">
                  {output.stdout}
                  {output.stderr}
                  {"\nExit status: " + output.retcode}
                </pre>
              )}
            </div>
            <div className="dialog-footer">
              <button type="button" onClick={() => setRun(null)}>
                Close
              </button>
              <button className="primary">Run script</button>
            </div>
          </form>
        </Dialog>
      )}
    </>
  );
}
export function ImportForm({ notify }: any) {
  const [text, setText] = useState(""),
    [tags, setTags] = useState(""),
    [retire, setRetire] = useState(false),
    [result, setResult] = useState<any>(null),
    [preview, setPreview] = useState<any[]>([]),
    [options, setOptions] = useState<any>({
      extract_ip: true,
      extract_dns: true,
      extract_signature: true,
      resurrect_retired_artifacts: true,
    }),
    [states, setStates] = useState<any[]>([]),
    [users, setUsers] = useState<any[]>([]),
    [busy, setBusy] = useState(false),
    [mapping, setMapping] = useState(""),
    [misp, setMisp] = useState("");
  useEffect(() => {
    api("/cfg_states?counts=false").then(setStates);
    api("/users").then((rows) => setUsers(rows.filter((u: any) => u.id)));
  }, []);
  const payload = () => ({
    ...options,
    retire_existing: retire,
    tags: tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
    metadata_field_mapping: mapping.trim() ? JSON.parse(mapping) : {},
  });

  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        try {
          setBusy(true);
          const r = await write("/import", {
            ...payload(),
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
        } finally {
          setBusy(false);
        }
      }}
    >
      <label>
        Rules or indicator text
        <textarea
          aria-label="Rules or indicator text"
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
            aria-label="Context tags"
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
      <label className="button">
        Read from file
        <input
          type="file"
          accept=".yar,.yara,.txt,.csv,.json"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (file) setText(await file.text());
          }}
        />
      </label>
      <details className="import-options">
        <summary>Import options</summary>
        <div className="form-grid">
          {[
            ["extract_signature", "Signatures"],
            ["extract_ip", "IP indicators"],
            ["extract_dns", "Domain indicators"],
            ["resurrect_retired_artifacts", "Restore retired indicators"],
          ].map(([key, label]) => (
            <label className="check-label" key={key}>
              <input
                type="checkbox"
                checked={!!options[key]}
                onChange={(e) =>
                  setOptions({ ...options, [key]: e.target.checked })
                }
              />
              {label}
            </label>
          ))}
          <label>
            State
            <select
              aria-label="Import state"
              value={options.shared_state || ""}
              onChange={(e) =>
                setOptions({ ...options, shared_state: e.target.value })
              }
            >
              <option value="">Imported</option>
              {states.map((row) => (
                <option key={row.id}>{row.state}</option>
              ))}
            </select>
          </label>
          <label>
            Owner
            <select
              aria-label="Import owner"
              value={options.shared_owner || ""}
              onChange={(e) =>
                setOptions({
                  ...options,
                  shared_owner: Number(e.target.value) || undefined,
                })
              }
            >
              <option value="">Me</option>
              {users.map((row) => (
                <option key={row.id} value={row.id}>
                  {row.email}
                </option>
              ))}
            </select>
          </label>
          <label>
            Reference
            <input
              aria-label="Import reference"
              value={options.shared_reference || ""}
              onChange={(e) =>
                setOptions({ ...options, shared_reference: e.target.value })
              }
            />
          </label>
          <label>
            Description
            <input
              aria-label="Import description"
              value={options.shared_description || ""}
              onChange={(e) =>
                setOptions({ ...options, shared_description: e.target.value })
              }
            />
          </label>
          <label>
            Source
            <input
              aria-label="Import source"
              value={options.source || ""}
              onChange={(e) =>
                setOptions({ ...options, source: e.target.value })
              }
            />
          </label>
          <label>
            Metadata mapping (JSON)
            <textarea
              aria-label="Metadata mapping"
              value={mapping}
              onChange={(e) => setMapping(e.target.value)}
              placeholder='{"original_key":"configured_key"}'
            />
          </label>
        </div>
      </details>
      <button
        type="button"
        disabled={busy || !text}
        onClick={async () => {
          try {
            const r = await write("/import", {
              ...payload(),
              import_text: text,
              autocommit: false,
            });
            setPreview(r.artifacts.map((a: any) => ({ ...a, selected: true })));
          } catch (e: any) {
            notify(e.message, true);
          }
        }}
      >
        Preview extraction
      </button>
      <button className="primary" disabled={busy}>
        Process import <ArrowUpRight size={16} />
      </button>
      {preview.length > 0 && (
        <section className="import-preview">
          <h3>Extracted artifacts</h3>
          {preview.map((a: any, i) => (
            <label className="check-label" key={i}>
              <input
                type="checkbox"
                checked={a.selected}
                onChange={(e) =>
                  setPreview((old) =>
                    old.map((row, j) =>
                      j === i ? { ...row, selected: e.target.checked } : row,
                    ),
                  )
                }
              />
              {a.type}: {a.artifact || a.rule?.rule_name}
            </label>
          ))}
          <button
            type="button"
            disabled={!preview.some((a) => a.selected)}
            onClick={async () => {
              try {
                const r = await write("/import/commit", {
                  ...payload(),
                  artifacts: preview
                    .filter((a) => a.selected)
                    .map(({ selected, ...a }) => a),
                });
                setResult(r.artifacts);
                setPreview([]);
                notify("Selected artifacts imported.");
              } catch (e: any) {
                notify(e.message, true);
              }
            }}
          >
            Import selected
          </button>
        </section>
      )}
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
      <details className="import-options">
        <summary>MISP warninglist</summary>
        <label>
          Warninglist JSON
          <textarea
            aria-label="Warninglist JSON"
            className="code-input"
            rows={5}
            value={misp}
            onChange={(e) => setMisp(e.target.value)}
          />
        </label>
        <button
          type="button"
          disabled={!misp.trim()}
          onClick={async () => {
            try {
              const r = await write("/whitelist/import-misp", JSON.parse(misp));
              notify(r.imported + " warninglist entries imported.");
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          Import warninglist
        </button>
      </details>
    </form>
  );
}
