import { CodeEditor, RevisionDiff } from "./CodeEditor";
import { UploadFiles } from "./UploadFiles";
import { permalink } from "../lib/links";
import { TagInput } from "./TagInput";
import { Select } from "./Select";
import { useState, useEffect, useId, useRef } from "react";
import {
  Link,
  Copy,
  FileCode2,
  Bell,
  Check,
  Download,
  Play,
  Trash2,
  History,
  Loader2,
  ChevronDown,
} from "lucide-react";
import { api, base, write } from "../lib/api";
import { date } from "../lib/format";
import { entityNames } from "../lib/navigation";
import { Badge, Empty, Dialog } from "./ui";
export function ArtifactEditor({
  page,
  initial,
  onClose,
  onSaved,
  notify,
  user,
}: any) {
  const [value, setValue] = useState<any>(initial),
    [tab, setTab] = useState("Content"),
    [states, setStates] = useState<any[]>([]),
    [definitions, setDefinitions] = useState<any[]>([]),
    [users, setUsers] = useState<any[]>([]),
    [busy, setBusy] = useState(false),
    [files, setFiles] = useState<any[]>(initial.files || []),
    [chosen, setChosen] = useState<Set<number>>(new Set()),
    [results, setResults] = useState<any>(null),
    [following, setFollowing] = useState(false),
    [categories, setCategories] = useState<any[]>([]),
    [countries, setCountries] = useState<any[]>([]),
    [discussion, setDiscussion] = useState<any[]>(initial.comments || []),
    [source, setSource] = useState(""),
    [compare, setCompare] = useState<any>(null),
    [leftRevision, setLeftRevision] = useState("current"),
    [rightRevision, setRightRevision] = useState(""),
    [comparing, setComparing] = useState(false),
    [keepRevision, setKeepRevision] = useState(false),
    [actionsOpen, setActionsOpen] = useState(false),
    [merging, setMerging] = useState(false),
    [mergeBusy, setMergeBusy] = useState(false),
    [mergeQuery, setMergeQuery] = useState(""),
    [destinations, setDestinations] = useState<any[]>([]),
    [destination, setDestination] = useState("");
  const actionsId = useId();
  const canEdit =
    initial.new ||
    user?.admin ||
    Number(initial.owner_user?.id ?? initial.owner_user_id) ===
      Number(user?.id);
  const baseline = useRef(initial);
  const dirty = JSON.stringify(value) !== JSON.stringify(baseline.current);
  const revisions = (initial.revisions || []).filter(
    (revision: any, index: number, rows: any[]) =>
      rows.findIndex((row) => row.revision === revision.revision) === index,
  );
  const close = () => {
    const pending = document
      .getElementById("artifact-form")
      ?.querySelector('[data-pending-entry="true"]');
    if (!busy && (!(dirty || pending) || confirm("Discard unsaved changes?")))
      onClose();
  };
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if (merging) return;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        if (!busy && canEdit)
          (
            document.getElementById("artifact-form") as HTMLFormElement
          )?.requestSubmit();
      }
      if (event.ctrlKey && event.key.toLowerCase() === "q") {
        event.preventDefault();
        close();
      }
    };
    document.addEventListener("keydown", shortcut);
    return () => document.removeEventListener("keydown", shortcut);
  }, [busy, dirty, merging, canEdit]);
  useEffect(() => {
    if (!merging) return;
    const timer = setTimeout(
      () =>
        api(
          "/yara_rules?short=true&page_size=20&include_comments=false&include_metadata=false&searches=" +
            encodeURIComponent(JSON.stringify({ name: mergeQuery })),
        ).then((r) =>
          setDestinations(r.data.filter((row: any) => row.id !== initial.id)),
        ),
      200,
    );
    return () => clearTimeout(timer);
  }, [merging, mergeQuery]);
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
    api("/cfg_states?counts=false").then((rows) => {
      setStates(rows);
      if (initial.new && !initial.state) {
        const state =
          rows.find((r: any) => r.is_staging_state)?.state ||
          rows[0]?.state ||
          "";
        baseline.current = { ...initial, state };
        setValue((v: any) => ({ ...v, state: v.state || state }));
      }
    });
    if (page === "yara_rules")
      api("/cfg_category_range_mapping").then(setCategories);
    if (page === "c2ips") api("/countries").then(setCountries);
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
    if (!canEdit) return;
    setBusy(true);
    try {
      const payload = {
        ...value,
        metadata_values: Object.fromEntries(
          definitions
            .filter((definition: any) => definition.active)
            .map((definition: any) => [
              definition.key,
              {
                value:
                  value.metadata_values?.[definition.key]?.value ??
                  definition.default ??
                  "",
              },
            ]),
        ),
        ...(isRule && !initial.new
          ? { do_not_bump_revision: keepRevision }
          : {}),
        asn: value.asn || "",
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
    <>
      {" "}
      <Dialog
        wide={isRule}
        dirty={dirty}
        busy={busy}
        title={
          initial.new
            ? "New " + (entityNames[page] || "release")
            : initial.name || initial.ip || initial.domain_name || initial.title
        }
        onClose={onClose}
      >
        {isRule && !initial.new && (
          <div className="tabs">
            {["Content", "Source", "Revisions", "Samples & files"].map((t) => (
              <button
                key={t}
                className={tab === t ? "active" : ""}
                onClick={async () => {
                  setTab(t);
                  if (t === "Source") {
                    try {
                      setSource(
                        await write("/yara_rules/copy", {
                          copy: { ids: [initial.id] },
                        }),
                      );
                    } catch (e: any) {
                      notify(e.message, true);
                    }
                  }
                }}
              >
                {t}
              </button>
            ))}
          </div>
        )}
        <div className="dialog-body">
          {tab === "Content" ? (
            <form id="artifact-form" onSubmit={save}>
              {!canEdit && (
                <p>
                  <Badge value="Read only" />
                </p>
              )}
              <fieldset
                className="form-grid artifact-fields artifact-form-fields"
                disabled={!canEdit}
              >
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
                {initial.release && (
                  <label className="check-label">
                    <input
                      type="checkbox"
                      checked={!!value.is_test_release}
                      onChange={(e) =>
                        field("is_test_release", e.target.checked ? 1 : 0)
                      }
                    />
                    Test release
                  </label>
                )}
                {!initial.release && (
                  <>
                    <label>
                      Workflow state
                      <Select
                        aria-label="Workflow state"
                        required
                        value={
                          typeof value.state === "object"
                            ? value.state.state
                            : value.state || ""
                        }
                        onChange={(e) => field("state", e.target.value)}
                      >
                        <option value="">Choose a state</option>
                        {value.state &&
                          !states.some(
                            (s: any) =>
                              s.state ===
                              (typeof value.state === "object"
                                ? value.state.state
                                : value.state),
                          ) && (
                            <option
                              value={
                                typeof value.state === "object"
                                  ? value.state.state
                                  : value.state
                              }
                            >
                              {typeof value.state === "object"
                                ? value.state.state
                                : value.state}
                            </option>
                          )}
                        {states.map((s) => (
                          <option key={s.id}>{s.state}</option>
                        ))}
                      </Select>
                    </label>
                    <label>
                      Owner
                      <Select
                        aria-label="Owner"
                        value={
                          value.owner_user?.id || value.owner_user_id || ""
                        }
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
                        {value.owner_user?.id &&
                          !users.some(
                            (u: any) => u.id === value.owner_user.id,
                          ) && (
                            <option value={value.owner_user.id}>
                              {value.owner_user.email}
                            </option>
                          )}
                        {users.map((u) => (
                          <option key={u.id} value={u.id}>
                            {u.email}
                          </option>
                        ))}
                      </Select>
                    </label>
                    {isRule && (
                      <label className="span2">
                        Category
                        <Select
                          aria-label="Category"
                          value={
                            typeof value.category === "object"
                              ? value.category.category
                              : value.category || ""
                          }
                          onChange={(e) => field("category", e.target.value)}
                        >
                          {!categories.some(
                            (c) =>
                              c.category ===
                              (typeof value.category === "object"
                                ? value.category.category
                                : value.category),
                          ) && (
                            <option>
                              {typeof value.category === "object"
                                ? value.category.category
                                : value.category || "Uncategorized"}
                            </option>
                          )}
                          {categories.map((category) => (
                            <option key={category.id}>
                              {category.category}
                            </option>
                          ))}
                        </Select>
                      </label>
                    )}
                    {page === "c2ips" && (
                      <>
                        <label>
                          ASN
                          <input
                            aria-label="ASN"
                            value={value.asn || ""}
                            onChange={(e) => field("asn", e.target.value)}
                          />
                        </label>
                        <label>
                          Country
                          <Select
                            aria-label="Country"
                            value={value.country?.countryCode2 || ""}
                            onChange={(e) =>
                              field(
                                "country",
                                e.target.value
                                  ? { countryCode2: e.target.value }
                                  : null,
                              )
                            }
                          >
                            <option value="">Unknown</option>
                            {countries.map((country) => (
                              <option
                                key={country.countryCode2}
                                value={country.countryCode2}
                              >
                                {country.countryName}
                              </option>
                            ))}
                          </Select>
                        </label>
                      </>
                    )}
                    {page === "c2dns" && (
                      <label>
                        Match type
                        <Select
                          aria-label="Match type"
                          value={value.match_type || "exact"}
                          onChange={(e) => field("match_type", e.target.value)}
                        >
                          <option value="exact">Exact</option>
                          <option value="wildcard">Wildcard</option>
                        </Select>
                      </label>
                    )}
                    {(page === "c2ips" || page === "c2dns") && (
                      <label className={page === "c2ips" ? "span2" : ""}>
                        Expiration (UTC)
                        <input
                          aria-label="Expiration (UTC)"
                          type="datetime-local"
                          value={value.expiration_timestamp?.slice(0, 16) || ""}
                          onChange={(e) =>
                            field(
                              "expiration_timestamp",
                              e.target.value || null,
                            )
                          }
                        />
                      </label>
                    )}
                    <label className={page === "tasks" ? "span2" : ""}>
                      Description
                      <textarea
                        aria-label="Description"
                        rows={3}
                        value={value.description || ""}
                        onChange={(e) => field("description", e.target.value)}
                      />
                    </label>
                    {page === "tasks" ? (
                      <label className="span2">
                        Final artifact
                        <textarea
                          aria-label="Final artifact"
                          rows={2}
                          value={value.final_artifact || ""}
                          onChange={(e) =>
                            field("final_artifact", e.target.value)
                          }
                        />
                      </label>
                    ) : (
                      <label>
                        References
                        <textarea
                          aria-label="References"
                          rows={3}
                          value={value.references || ""}
                          onChange={(e) => field("references", e.target.value)}
                        />
                      </label>
                    )}
                    {isRule && (
                      <fieldset className="form-section span2">
                        <legend>Detection logic</legend>
                        <div className="form-grid">
                          <div className="field">
                            <span>Strings</span>
                            <CodeEditor
                              label="Strings"
                              className="code-input"
                              value={String(value.strings || "").replace(
                                /^\s*strings:\s*/,
                                "",
                              )}
                              onChange={(e) => field("strings", e.target.value)}
                            />
                          </div>
                          <div className="field">
                            <span>Condition</span>
                            <CodeEditor
                              label="Condition"
                              className="code-input"
                              value={String(value.condition || "").replace(
                                /^\s*condition:\s*/,
                                "",
                              )}
                              onChange={(e) =>
                                field("condition", e.target.value)
                              }
                            />
                          </div>
                          <div className="field span2">
                            <span>Imports</span>
                            <CodeEditor
                              label="Imports"
                              className="code-input compact-editor"
                              value={value.imports || ""}
                              onChange={(e) => field("imports", e.target.value)}
                            />
                          </div>
                        </div>
                      </fieldset>
                    )}
                    {isRule && (
                      <fieldset className="form-section span2">
                        <legend>MITRE ATT&CK</legend>
                        <div className="form-grid">
                          <div className="field ">
                            <span>MITRE tactics</span>
                            <TagInput
                              label="MITRE tactics"
                              suggest={false}
                              placeholder="Add identifier…"
                              value={value.mitre_tactics || []}
                              onChange={(ids: string[]) =>
                                field("mitre_tactics", ids)
                              }
                            />
                          </div>
                          <div className="field ">
                            <span>MITRE techniques</span>
                            <TagInput
                              label="MITRE techniques"
                              suggest={false}
                              placeholder="Add identifier…"
                              value={value.mitre_techniques || []}
                              onChange={(ids: string[]) =>
                                field("mitre_techniques", ids)
                              }
                            />
                          </div>
                          <div className="field span2">
                            <span>MITRE sub-techniques</span>
                            <TagInput
                              label="MITRE sub-techniques"
                              suggest={false}
                              placeholder="Add identifier…"
                              value={value.mitre_sub_techniques || []}
                              onChange={(ids: string[]) =>
                                field("mitre_sub_techniques", ids)
                              }
                            />
                          </div>
                        </div>
                      </fieldset>
                    )}
                    <div className="field span2">
                      <span>Tags</span>
                      <TagInput
                        value={value.tags || []}
                        onChange={(tags: string[]) => field("tags", tags)}
                      />
                    </div>
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
                          <label
                            key={definition.id}
                            className={
                              definition.type === "multiline_comment"
                                ? "span2"
                                : undefined
                            }
                          >
                            {definition.key}
                            {definition.choices?.length ? (
                              <Select
                                required={!!definition.required}
                                value={item?.value ?? definition.default ?? ""}
                                onChange={(e) => change(e.target.value)}
                              >
                                <option value="">Choose a value</option>
                                {definition.choices.map((c: any) => (
                                  <option key={c.id} value={c.choice}>
                                    {c.choice}
                                  </option>
                                ))}
                              </Select>
                            ) : definition.type === "multiline_comment" ? (
                              <textarea
                                required={!!definition.required}
                                value={item?.value ?? definition.default ?? ""}
                                onChange={(e) => change(e.target.value)}
                              />
                            ) : (
                              <input
                                required={!!definition.required}
                                ref={(element) =>
                                  element?.setCustomValidity(
                                    definition.type === "integer" &&
                                      element.value &&
                                      !Number.isInteger(Number(element.value))
                                      ? "Enter a whole number."
                                      : "",
                                  )
                                }
                                value={
                                  definition.type === "date"
                                    ? String(
                                        item?.value ?? definition.default ?? "",
                                      ).slice(0, 10)
                                    : (item?.value ?? definition.default ?? "")
                                }
                                type={
                                  ["number", "integer"].includes(
                                    definition.type,
                                  )
                                    ? "number"
                                    : definition.type === "date"
                                      ? "date"
                                      : "text"
                                }
                                onChange={(e) => change(e.target.value)}
                              />
                            )}
                          </label>
                        );
                      })}
                    <div className="span2">
                      {isRule && !initial.new && (
                        <ConfidenceSchedule
                          ruleId={initial.id}
                          notify={notify}
                        />
                      )}
                    </div>
                    {!!discussion.length && (
                      <section className="span2">
                        <h3>Review discussion</h3>
                        {discussion.map((comment: any) => (
                          <article className="review-comment" key={comment.id}>
                            <p>{comment.comment}</p>
                            {user?.admin && (
                              <button
                                type="button"
                                className="text-danger"
                                onClick={async () => {
                                  if (!confirm("Delete this comment?")) return;
                                  try {
                                    await api("/comments/" + comment.id, {
                                      method: "DELETE",
                                    });
                                    setDiscussion((old) =>
                                      old.filter((c) => c.id !== comment.id),
                                    );
                                    notify("Comment deleted.");
                                  } catch (e: any) {
                                    notify(e.message, true);
                                  }
                                }}
                              >
                                Delete comment
                              </button>
                            )}
                            <small>
                              {comment.user?.email} ·{" "}
                              {date(comment.date_created)}
                            </small>
                          </article>
                        ))}
                      </section>
                    )}
                    <label className="span2">
                      Draft comment <small>Saved with your changes</small>
                      <textarea
                        aria-label="Draft comment"
                        rows={3}
                        value={value.new_comment || ""}
                        onChange={(e) => field("new_comment", e.target.value)}
                        placeholder="Add review context…"
                      />
                    </label>
                  </>
                )}
              </fieldset>
            </form>
          ) : tab === "Source" ? (
            <div>
              <div className="field">
                <span>YARA source</span>
                <CodeEditor
                  label="YARA source"
                  className="code-input source-editor"
                  readOnly
                  value={source}
                />
              </div>
              <div className="button-row source-actions">
                <button
                  onClick={async () => {
                    await navigator.clipboard.writeText(source);
                    notify("YARA copied.");
                  }}
                >
                  <Copy size={15} />
                  Copy YARA
                </button>
                <a
                  className="button"
                  download={(initial.name || "signature") + ".yar"}
                  href={
                    "data:text/plain;charset=utf-8," +
                    encodeURIComponent(source)
                  }
                >
                  <Download size={15} />
                  Download YARA
                </a>
              </div>
            </div>
          ) : tab === "Revisions" ? (
            <div>
              {!!revisions.length && (
                <div className="revision-picker">
                  <label>
                    First revision
                    <Select
                      aria-label="First revision"
                      value={leftRevision}
                      onChange={(e: any) => {
                        setLeftRevision(e.target.value);
                        setCompare(null);
                      }}
                    >
                      <option value="current">
                        Current ({initial.revision})
                      </option>
                      {revisions.map((r: any) => (
                        <option key={r.revision} value={r.revision}>
                          Revision {r.revision}
                        </option>
                      ))}
                    </Select>
                  </label>
                  <label>
                    Second revision
                    <Select
                      aria-label="Second revision"
                      value={rightRevision}
                      onChange={(e: any) => {
                        setRightRevision(e.target.value);
                        setCompare(null);
                      }}
                    >
                      <option value="">Choose revision</option>
                      {revisions.map((r: any) => (
                        <option key={r.revision} value={r.revision}>
                          Revision {r.revision}
                        </option>
                      ))}
                    </Select>
                  </label>
                  <button
                    disabled={
                      !rightRevision ||
                      leftRevision === rightRevision ||
                      comparing
                    }
                    onClick={async () => {
                      setComparing(true);
                      try {
                        const getSource = (r: string) =>
                          r === "current"
                            ? write("/yara_rules/copy", {
                                copy: { ids: [initial.id] },
                              })
                            : api(
                                "/yara_rules/" + initial.id + "/revision/" + r,
                              );
                        const [left, right] = await Promise.all([
                          getSource(leftRevision),
                          getSource(rightRevision),
                        ]);
                        setCompare({
                          revision: rightRevision,
                          source: right,
                          current: left,
                          left: leftRevision,
                          right: rightRevision,
                        });
                      } catch (e: any) {
                        notify(e.message, true);
                      } finally {
                        setComparing(false);
                      }
                    }}
                  >
                    <History size={15} />
                    {comparing ? "Comparing…" : "Compare revisions"}
                  </button>
                </div>
              )}
              {compare && (
                <div>
                  <div className="section-top">
                    <h3>Revision comparison</h3>
                    <button onClick={() => setCompare(null)}>
                      Close comparison
                    </button>
                  </div>
                  <div className="revision-labels">
                    <strong>
                      {compare.left && compare.left !== "current"
                        ? "Revision " + compare.left
                        : "Current revision " + initial.revision}
                    </strong>
                    <strong>
                      Revision {compare.right || compare.revision}
                    </strong>
                  </div>
                  <RevisionDiff left={compare.current} right={compare.source} />
                </div>
              )}

              {revisions.length ? (
                revisions.map((r: any) => (
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
                          const [source, current] = await Promise.all([
                            api(
                              "/yara_rules/" +
                                initial.id +
                                "/revision/" +
                                r.revision,
                            ),
                            write("/yara_rules/copy", {
                              copy: { ids: [initial.id] },
                            }),
                          ]);
                          setCompare({ revision: r.revision, source, current });
                        } catch (e: any) {
                          notify(e.message, true);
                        }
                      }}
                    >
                      Compare with current
                    </button>
                    <button
                      onClick={async () => {
                        try {
                          if (
                            !confirm(
                              "Restore revision " +
                                r.revision +
                                " as a new revision?",
                            )
                          )
                            return;
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
                <UploadFiles
                  entityId={initial.id}
                  notify={notify}
                  onUploaded={async () =>
                    setFiles(
                      await api("/files?entity_type=1&entity_id=" + initial.id),
                    )
                  }
                />
              </div>
              {user?.admin && files.some((f) => f.parent_sha1) && (
                <details className="sample-folders">
                  <summary>Sample folders</summary>
                  {files
                    .filter(
                      (f) =>
                        !f.parent_sha1 &&
                        files.some((child) => child.parent_sha1 === f.sha1),
                    )
                    .map((f) => (
                      <div className="file-group-row" key={f.id}>
                        <code>{f.filename}</code>
                        <button
                          className="text-danger"
                          onClick={async () => {
                            if (
                              !confirm(
                                "Delete " +
                                  f.filename +
                                  " and all extracted files?",
                              )
                            )
                              return;
                            try {
                              await api("/files/" + f.id + "?path=1", {
                                method: "DELETE",
                              });
                              setFiles(
                                await api(
                                  "/files?entity_type=1&entity_id=" +
                                    initial.id,
                                ),
                              );
                              setChosen(new Set());
                              notify("Sample group deleted.");
                            } catch (e: any) {
                              notify(e.message, true);
                            }
                          }}
                        >
                          <Trash2 size={14} />
                          Delete group
                        </button>
                      </div>
                    ))}
                  {files
                    .filter(
                      (f, index, rows) =>
                        f.parent_sha1 &&
                        f.path &&
                        rows.findIndex(
                          (r) =>
                            r.parent_sha1 === f.parent_sha1 &&
                            r.path === f.path,
                        ) === index,
                    )
                    .map((f) => (
                      <div className="file-group-row" key={f.id}>
                        <code>{f.path}</code>
                        <button
                          className="text-danger"
                          onClick={async () => {
                            if (
                              !confirm(
                                "Delete the extracted folder " + f.path + "?",
                              )
                            )
                              return;
                            try {
                              await api("/files/" + f.id + "?path=1", {
                                method: "DELETE",
                              });
                              setFiles(
                                await api(
                                  "/files?entity_type=1&entity_id=" +
                                    initial.id,
                                ),
                              );
                              setChosen(new Set());
                              notify("Folder deleted.");
                            } catch (e: any) {
                              notify(e.message, true);
                            }
                          }}
                        >
                          <Trash2 size={14} />
                          Delete folder
                        </button>
                      </div>
                    ))}
                </details>
              )}
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
                    {file.path && <small>{file.path}</small>}
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
              <div className="button-row sample-actions">
                <button
                  hidden={!user?.admin}
                  disabled={!chosen.size}
                  onClick={async () => {
                    try {
                      if (!confirm("Delete selected files?")) return;
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
              </div>
              <div className="section-top">
                <h3>Match history</h3>
                <button
                  onClick={async () =>
                    setResults(
                      await api(
                        "/yara_rules/" + initial.id + "/sample-results",
                      ),
                    )
                  }
                >
                  Refresh outcomes
                </button>
              </div>
              <label className="check-label sample-history-options">
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
        <div className="dialog-footer artifact-footer">
          {!initial.new && (
            <span className="muted">
              {initial.uuid
                ? initial.uuid
                : initial.id
                  ? "Record #" + initial.id
                  : ""}
            </span>
          )}
          <div className="button-row">
            {!initial.new && (
              <button
                className="record-actions-toggle"
                aria-expanded={actionsOpen}
                aria-controls={actionsId}
                onClick={() => setActionsOpen(!actionsOpen)}
              >
                Record actions <ChevronDown size={14} />
              </button>
            )}
            <div
              id={actionsId}
              className={"record-actions " + (actionsOpen ? "open" : "")}
            >
              {!initial.new && (
                <button
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(
                        permalink(page, initial.id),
                      );
                      notify("Permalink copied.");
                    } catch {
                      notify(
                        "Could not copy the link. Copy it from the address bar.",
                        true,
                      );
                    }
                  }}
                >
                  <Link size={15} />
                  Copy permalink
                </button>
              )}
              {isRule && !initial.new && (
                <label className="check-label revision-option">
                  <input
                    type="checkbox"
                    checked={keepRevision}
                    onChange={(e) => setKeepRevision(e.target.checked)}
                  />
                  Keep revision number
                </label>
              )}
              {!initial.new && (
                <button
                  onClick={async () => {
                    try {
                      const type = {
                        yara_rules: 1,
                        c2dns: 2,
                        c2ips: 3,
                        tasks: 4,
                      }[page as "yara_rules"];
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
                        following
                          ? "Stopped following."
                          : "Following this record.",
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
              {canEdit &&
                isRule &&
                (initial.active === false || initial.active === 0) && (
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
              {canEdit &&
                !initial.new &&
                !initial.release &&
                initial.active !== false &&
                initial.active !== 0 && (
                  <button
                    className="text-danger"
                    onClick={async () => {
                      if (!confirm("Deactivate this record?")) return;
                      try {
                        await api("/" + page + "/" + initial.id, {
                          method: "DELETE",
                        });
                        notify("Record deactivated.");
                        onSaved();
                      } catch (e: any) {
                        notify(e.message, true);
                      }
                    }}
                  >
                    Deactivate
                  </button>
                )}
              {isRule && !initial.new && (
                <button onClick={() => setMerging(true)}>Merge into…</button>
              )}
              {canEdit &&
                !isRule &&
                !initial.new &&
                (initial.active === false || initial.active === 0) && (
                  <button
                    onClick={async () => {
                      try {
                        await write(
                          "/artifacts/" +
                            ({ c2ips: 3, c2dns: 2, tasks: 4 } as any)[page] +
                            "/" +
                            initial.id +
                            "/restore",
                          {},
                        );
                        onSaved();
                        notify("Record restored.");
                      } catch (e: any) {
                        notify(e.message, true);
                      }
                    }}
                  >
                    Restore record
                  </button>
                )}
            </div>
            <button onClick={close}>Close</button>
            {tab === "Content" && canEdit && (
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
      {merging && (
        <Dialog
          title="Merge into another signature"
          busy={mergeBusy}
          dirty={!!destination}
          onClose={() => setMerging(false)}
        >
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              if (mergeBusy) return;
              setMergeBusy(true);
              try {
                await write("/yara_rules/merge_signatures_by_id", {
                  merge_from_id: initial.id,
                  merge_to_id: Number(destination),
                });
                setMerging(false);
                onSaved();
                notify("Signature merged.");
              } catch (error: any) {
                notify(error.message, true);
              } finally {
                setMergeBusy(false);
              }
            }}
          >
            <div className="dialog-body">
              <label>
                Find destination
                <input
                  aria-label="Find destination"
                  value={mergeQuery}
                  onChange={(e) => setMergeQuery(e.target.value)}
                />
              </label>
              <label>
                Destination signature
                <Select
                  aria-label="Destination signature"
                  required
                  value={destination}
                  onChange={(e) => setDestination(e.target.value)}
                >
                  <option value="">Choose a signature</option>
                  {destinations.map((row) => (
                    <option key={row.id} value={row.id}>
                      {row.name}
                    </option>
                  ))}
                </Select>
              </label>
            </div>
            <div className="dialog-footer">
              <button
                type="button"
                disabled={mergeBusy}
                onClick={() => {
                  if (!destination || confirm("Discard unsaved changes?"))
                    setMerging(false);
                }}
              >
                Cancel
              </button>
              <button className="primary" disabled={!destination || mergeBusy}>
                Merge signatures
              </button>
            </div>
          </form>
        </Dialog>
      )}
    </>
  );
}
export function ConfidenceSchedule({ ruleId, notify }: any) {
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
            aria-label="Confidence"
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
            aria-label="Apply on"
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
