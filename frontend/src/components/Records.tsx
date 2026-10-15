import { useState, useEffect, useRef } from "react";
import {
  Search,
  Plus,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Filter,
  X,
  Download,
  Copy,
  GitMerge,
  Trash2,
} from "lucide-react";
import { api, write, base } from "../lib/api";
import { fmt, date } from "../lib/format";
import { entityNames } from "../lib/navigation";
import { Badge, IconButton, Empty, Dialog, Loading } from "./ui";
import { ArtifactEditor } from "./ArtifactEditor";

type RuleFilter = { field: string; op: string; value: string };
const kinds: any = { yara_rules: 1, c2dns: 2, c2ips: 3, tasks: 4 };
const nameKeys: any = {
  yara_rules: "name",
  c2ips: "ip",
  c2dns: "domain_name",
  tasks: "title",
  activity_log: "activity_text",
  releases: "name",
  jobs: "kind",
};
const timestampKeys: any = {
  yara_rules: "last_revision_date",
  c2ips: "date_modified",
  c2dns: "date_modified",
  tasks: "date_modified",
  activity_log: "activity_date",
  releases: "date_created",
  jobs: "created_at",
};
function downloadText(text: string, name: string) {
  const url = URL.createObjectURL(
    new Blob([text], { type: "text/plain;charset=utf-8" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Records({ page, version, notify, refresh, user }: any) {
  const key = "threatkb.table." + page;
  const saved = () => {
    try {
      return JSON.parse(sessionStorage.getItem(key) || "{}");
    } catch {
      return {};
    }
  };
  const [prefs] = useState(saved),
    [query, setQuery] = useState(prefs.q || ""),
    [debounced, setDebounced] = useState(prefs.q || ""),
    [index, setIndex] = useState(prefs.index || 0),
    [size, setSize] = useState(prefs.size || 25),
    [view, setView] = useState(prefs.view || "Active Only"),
    [sort, setSort] = useState(prefs.sort || timestampKeys[page] || "id"),
    [direction, setDirection] = useState(prefs.direction || "DESC"),
    [filters, setFilters] = useState<RuleFilter[]>(prefs.filters || []),
    [operator, setOperator] = useState(prefs.operator || "and"),
    [filterOpen, setFilterOpen] = useState(false),
    [newFilter, setNewFilter] = useState<RuleFilter>({
      field: nameKeys[page] || "name",
      op: "contains",
      value: "",
    }),
    [data, setData] = useState<any>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [selected, setSelected] = useState<Set<number>>(new Set()),
    [editor, setEditor] = useState<any>(null),
    [extra, setExtra] = useState<any>(null),
    [bulk, setBulk] = useState(false),
    [source, setSource] = useState<any>(null),
    [wrap, setWrap] = useState(false),
    [states, setStates] = useState<any[]>([]),
    [users, setUsers] = useState<any[]>([]),
    [categories, setCategories] = useState<any[]>([]),
    [definitions, setDefinitions] = useState<any[]>([]),
    [showColumns, setShowColumns] = useState(false),
    [days, setDays] = useState(45),
    [visibleColumns, setVisibleColumns] = useState<string[]>(
      prefs.columns || ["owner", "category", "tags", "updated"],
    );
  const allRef = useRef<HTMLInputElement>(null);
  const editable = !!kinds[page];
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebounced(query);
      setIndex(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [query]);
  useEffect(() => {
    sessionStorage.setItem(
      key,
      JSON.stringify({
        q: query,
        index,
        size,
        view,
        sort,
        direction,
        filters,
        operator,
        columns: visibleColumns,
      }),
    );
  }, [
    query,
    index,
    size,
    view,
    sort,
    direction,
    filters,
    operator,
    visibleColumns,
  ]);
  useEffect(() => {
    setSelected(new Set());
  }, [page, index, size, debounced, view, filters, sort, direction]);
  useEffect(() => {
    if (allRef.current)
      allRef.current.indeterminate =
        selected.size > 0 && selected.size < (data?.data?.length || 0);
  }, [selected, data]);
  useEffect(() => {
    if (!editable) return;
    api("/cfg_states?counts=false&for_filter=true")
      .then(setStates)
      .catch((e: any) => notify(e.message, true));
    api("/users").then(setUsers);
    api("/metadata?artifact_type=" + kinds[page]).then((fields) => {
      setDefinitions(fields);
      if (!prefs.columns)
        setVisibleColumns((old) => [
          ...new Set([
            ...old,
            ...fields
              .filter((d: any) => d.show_in_table)
              .map((d: any) => "metadata:" + d.key),
          ]),
        ]);
    });
    if (page === "yara_rules")
      api("/cfg_category_range_mapping").then(setCategories);
  }, [page]);
  const recordId = new URLSearchParams(location.hash.split("?")[1] || "").get(
    "id",
  );
  useEffect(() => {
    const id = recordId;
    if (id && editable)
      api("/" + page + "/" + id)
        .then(setEditor)
        .catch((e: any) => notify(e.message, true));
  }, [page, recordId]);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    const searches: any = {};
    for (const filter of filters)
      searches[filter.field] = { op: filter.op, value: filter.value };
    const params = new URLSearchParams({
      page_number: String(index),
      page_size: String(size),
      limit: String(size),
      view,
      short: "true",
      include_comments: "false",
      sort_by: sort,
      sort_dir: direction,
      operator,
      searches: JSON.stringify(searches),
    });
    if (debounced) params.set("q", debounced);
    if (page === "activity_log") params.set("since", String(days));
    api("/" + page + "?" + params, { signal: controller.signal })
      .then((value) => {
        if (controller.signal.aborted) return;
        setData(
          Array.isArray(value)
            ? { data: value, total_count: value.length }
            : value,
        );
      })
      .catch((e: any) => {
        if (e.name !== "AbortError") setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [
    page,
    version,
    index,
    size,
    debounced,
    view,
    sort,
    direction,
    filters,
    operator,
    days,
  ]);
  const updateFilters = (next: RuleFilter[]) => {
    setFilters(next);
    setIndex(0);
  };
  const quick = (field: string, value: string) =>
    updateFilters([
      ...filters.filter((f) => f.field !== field),
      ...(value ? [{ field, op: value === "~" ? "empty" : "eq", value }] : []),
    ]);
  const open = async (row: any) => {
    try {
      if (editable) setEditor(await api("/" + page + "/" + row.id));
      else setExtra(row);
    } catch (e: any) {
      notify(e.message, true);
    }
  };
  const columns: any[] = [
    {
      key: nameKeys[page],
      label: editable
        ? page === "yara_rules"
          ? "Name"
          : page === "tasks"
            ? "Title"
            : "Indicator"
        : page === "jobs"
          ? "Job"
          : "Name / activity",
    },
    ...(page === "yara_rules" ? [{ key: "eventid", label: "EventID" }] : []),
    {
      key:
        page === "jobs"
          ? "status"
          : page === "activity_log"
            ? "activity_type"
            : page === "releases"
              ? null
              : "state",
      label: "State",
    },
    ...(editable && visibleColumns.includes("owner")
      ? [{ key: "owner_user.email", label: "Owner" }]
      : []),
    ...(page === "yara_rules" && visibleColumns.includes("category")
      ? [{ key: "category", label: "Category" }]
      : []),
    ...(editable && visibleColumns.includes("tags")
      ? [{ key: null, label: "Tags", type: "tags" }]
      : []),
    ...definitions
      .filter((d) => visibleColumns.includes("metadata:" + d.key))
      .map((d) => ({
        key: "metadata:" + d.key,
        label: d.key,
        type: "metadata",
        field: d.key,
      })),
    ...(visibleColumns.includes("updated")
      ? [{ key: timestampKeys[page], label: "Updated" }]
      : []),
  ];
  const fieldOptions: any[] = [
    [nameKeys[page], "Name"],
    ["state", "State"],
    ["owner_user.email", "Owner"],
    ["tags", "Tags"],
    ["comments", "Comments"],
    ["description", "Description"],
    ...(page === "yara_rules"
      ? [
          ["category", "Category"],
          ["eventid", "EventID"],
        ]
      : []),
    ...[...definitions.map((d) => [d.key, d.key])],
  ];
  async function selectedSource(mode: string) {
    try {
      const value = await write("/yara_rules/copy", {
        copy: { ids: [...selected] },
      });
      if (mode === "download") downloadText(value, "signatures.yar");
      else if (mode === "clipboard") {
        await navigator.clipboard.writeText(value);
        notify("YARA copied.");
      } else setSource({ text: value, merged: false });
    } catch (e: any) {
      notify(e.message, true);
    }
  }
  async function deactivate() {
    if (!confirm("Deactivate " + selected.size + " selected records?")) return;
    try {
      await write(
        "/" + page + "/batch/delete",
        { batch: { ids: [...selected] } },
        "PUT",
      );
      setSelected(new Set());
      refresh();
      notify("Selected records deactivated.");
    } catch (e: any) {
      notify(e.message, true);
    }
  }
  useEffect(() => {
    if (
      page !== "jobs" ||
      !data?.data?.some((j: any) => ["queued", "running"].includes(j.status))
    )
      return;
    const timer = setTimeout(refresh, 2000);
    return () => clearTimeout(timer);
  }, [page, data]);
  const total = data?.total_count || 0,
    pages = Math.max(1, Math.ceil(total / size));
  return (
    <>
      {page === "activity_log" && <ActivityDistribution days={days} />}
      <section className="panel records-panel" aria-busy={loading}>
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={16} />
            <input
              aria-label="Search records"
              placeholder={
                page === "yara_rules" ? "Search signatures" : "Search records"
              }
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <IconButton label="Clear search" onClick={() => setQuery("")}>
                <X size={14} />
              </IconButton>
            )}
          </div>
          <div className="toolbar-actions">
            {page === "activity_log" && (
              <select
                aria-label="Activity period"
                value={days}
                onChange={(e) => {
                  setDays(Number(e.target.value));
                  setIndex(0);
                }}
              >
                {[1, 7, 30, 45, 90, 365].map((day) => (
                  <option key={day} value={day}>
                    Last {day} days
                  </option>
                ))}
              </select>
            )}
            {editable && (
              <>
                <select
                  aria-label="Filter by state"
                  value={filters.find((f) => f.field === "state")?.value || ""}
                  onChange={(e) => quick("state", e.target.value)}
                >
                  <option value="">All states</option>
                  {states.map((state) => (
                    <option key={state.id}>{state.state}</option>
                  ))}
                </select>
                <select
                  aria-label="Record visibility"
                  value={view}
                  onChange={(e) => {
                    setView(e.target.value);
                    setIndex(0);
                  }}
                >
                  <option>Active Only</option>
                  <option>Inactive Only</option>
                  <option>All</option>
                </select>
                <button
                  aria-expanded={filterOpen}
                  onClick={() => setFilterOpen(!filterOpen)}
                >
                  <Filter size={15} />
                  Filters{filters.length > 0 ? " (" + filters.length + ")" : ""}
                </button>
              </>
            )}
            <details
              className="column-menu"
              open={showColumns}
              onToggle={(e) => setShowColumns(e.currentTarget.open)}
            >
              <summary>Columns</summary>
              <div>
                {[
                  ["owner", "Owner"],
                  ...(page === "yara_rules" ? [["category", "Category"]] : []),
                  ["tags", "Tags"],
                  ["updated", "Updated"],
                  ...definitions.map((d) => ["metadata:" + d.key, d.key]),
                ].map(([value, label]) => (
                  <label key={value}>
                    <input
                      type="checkbox"
                      checked={visibleColumns.includes(value)}
                      onChange={() =>
                        setVisibleColumns((old) =>
                          old.includes(value)
                            ? old.filter((v) => v !== value)
                            : [...old, value],
                        )
                      }
                    />
                    {label}
                  </label>
                ))}
                <label>
                  <input
                    type="checkbox"
                    checked={wrap}
                    onChange={(e) => setWrap(e.target.checked)}
                  />
                  Wrap cell text
                </label>
              </div>
            </details>
            {editable && (
              <button
                className="primary"
                disabled={!states.length}
                onClick={() =>
                  setEditor({
                    new: true,
                    state: states.some((s) => s.state === "Vetting")
                      ? "Vetting"
                      : states[0]?.state || "",
                    category:
                      categories.find((c) => c.category === "Uncategorized")
                        ?.category ||
                      categories[0]?.category ||
                      "Uncategorized",
                    tags: [],
                    strings: "",
                    condition: "true",
                    asn: "",
                    match_type: "exact",
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
        {filterOpen && (
          <form
            className="filter-builder"
            onSubmit={(e) => {
              e.preventDefault();
              updateFilters([
                ...filters.filter((f) => f.field !== newFilter.field),
                newFilter,
              ]);
              setNewFilter({ ...newFilter, value: "" });
            }}
          >
            <label>
              Field
              <select
                aria-label="Field"
                value={newFilter.field}
                onChange={(e) =>
                  setNewFilter({ ...newFilter, field: e.target.value })
                }
              >
                {fieldOptions.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Match
              <select
                aria-label="Match"
                value={newFilter.op}
                onChange={(e) =>
                  setNewFilter({ ...newFilter, op: e.target.value })
                }
              >
                {[
                  ["contains", "contains"],
                  ["eq", "equals"],
                  ["not_contains", "does not contain"],
                  ["neq", "does not equal"],
                  ["prefix", "starts with"],
                  ["empty", "is empty"],
                  ["before_now", "is before now"],
                  ["after_now", "is after now"],
                ].map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Value
              <input
                aria-label="Value"
                disabled={["empty", "before_now", "after_now"].includes(
                  newFilter.op,
                )}
                value={newFilter.value}
                onChange={(e) =>
                  setNewFilter({ ...newFilter, value: e.target.value })
                }
              />
            </label>
            <button>Add filter</button>
            <label className="check-label">
              <input
                type="checkbox"
                checked={operator === "or"}
                onChange={(e) => setOperator(e.target.checked ? "or" : "and")}
              />
              Match any filter
            </label>
          </form>
        )}
        {filters.length > 0 && (
          <div className="filter-chips">
            {filters.map((filter, index) => (
              <button
                key={filter.field}
                aria-label={
                  "Remove " +
                  (fieldOptions.find((f) => f[0] === filter.field)?.[1] ||
                    filter.field) +
                  " filter"
                }
                onClick={() =>
                  updateFilters(filters.filter((_, i) => i !== index))
                }
              >
                {fieldOptions.find((f) => f[0] === filter.field)?.[1] ||
                  filter.field}{" "}
                {filter.op.replaceAll("_", " ")} {filter.value}
                <X size={12} />
              </button>
            ))}
            <button onClick={() => updateFilters([])}>Clear filters</button>
          </div>
        )}
        {editable && selected.size > 0 && (
          <div className="selection-bar">
            <strong>{selected.size} selected</strong>
            <button onClick={() => setBulk(true)}>Edit selected</button>
            {page === "yara_rules" && (
              <>
                <button onClick={() => selectedSource("download")}>
                  <Download size={15} />
                  Export YARA
                </button>
                <button onClick={() => selectedSource("clipboard")}>
                  <Copy size={15} />
                  Copy YARA
                </button>
                <button
                  disabled={selected.size < 2 || selected.size > 20}
                  onClick={async () => {
                    try {
                      const r = await write("/yara_rules/merge_signatures", {
                        signature_ids: [...selected],
                      });
                      setSource({ text: r.merged_signature, merged: true });
                    } catch (e: any) {
                      notify(e.message, true);
                    }
                  }}
                >
                  <GitMerge size={15} />
                  Merge selected
                </button>
              </>
            )}
            <button className="danger" onClick={deactivate}>
              <Trash2 size={14} />
              Deactivate
            </button>
            <button onClick={() => setSelected(new Set())}>
              Clear selection
            </button>
          </div>
        )}
        {error ? (
          <div className="inline-error" role="alert">
            {error}
            <button onClick={refresh}>Retry</button>
          </div>
        ) : !data ? (
          <Loading />
        ) : (
          <div className="table-scroll">
            <table
              className={"records-table " + (wrap ? "wrap" : "")}
              id="records-table"
            >
              <thead>
                <tr>
                  {editable && (
                    <th className="checkbox-cell">
                      <input
                        ref={allRef}
                        type="checkbox"
                        aria-label="Select all visible records"
                        checked={
                          data.data.length > 0 &&
                          data.data.every((row: any) => selected.has(row.id))
                        }
                        onChange={(e) =>
                          setSelected(
                            e.target.checked
                              ? new Set(data.data.map((row: any) => row.id))
                              : new Set(),
                          )
                        }
                      />
                    </th>
                  )}
                  {columns.map((column, index) => (
                    <th
                      scope="col"
                      key={column.key || column.label}
                      aria-sort={
                        sort === column.key
                          ? direction === "ASC"
                            ? "ascending"
                            : "descending"
                          : undefined
                      }
                    >
                      {column.key ? (
                        <button
                          className="sort-button"
                          aria-label={"Sort by " + column.label}
                          onClick={() => {
                            setDirection(
                              sort === column.key && direction === "ASC"
                                ? "DESC"
                                : "ASC",
                            );
                            setSort(column.key);
                            setIndex(0);
                          }}
                        >
                          {column.label}
                          {sort === column.key ? (
                            direction === "ASC" ? (
                              <ArrowUp size={13} />
                            ) : (
                              <ArrowDown size={13} />
                            )
                          ) : (
                            <ArrowUpDown size={12} />
                          )}
                        </button>
                      ) : (
                        column.label
                      )}
                    </th>
                  ))}
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.data.map((row: any) => (
                  <tr
                    key={row.id}
                    className={selected.has(row.id) ? "row-selected" : ""}
                  >
                    {editable && (
                      <td className="checkbox-cell">
                        <input
                          type="checkbox"
                          aria-label={
                            "Select " + (row[nameKeys[page]] || row.id)
                          }
                          checked={selected.has(row.id)}
                          onChange={() =>
                            setSelected((old) => {
                              const next = new Set(old);
                              next.has(row.id)
                                ? next.delete(row.id)
                                : next.add(row.id);
                              return next;
                            })
                          }
                        />
                      </td>
                    )}
                    {columns.map((column, colIndex) => (
                      <td
                        key={column.key || column.label}
                        className={
                          colIndex === 0
                            ? "name-cell"
                            : column.type === "tags"
                              ? "tags-cell"
                              : ""
                        }
                      >
                        {colIndex === 0 ? (
                          <button
                            className="record-name"
                            disabled={loading}
                            title={row.uuid || String(row.id)}
                            onClick={() => open(row)}
                          >
                            {row[nameKeys[page]] ||
                              row.name ||
                              row.activity_text ||
                              row.id}
                            {page === "jobs" && (
                              <small>
                                {row.id.slice(0, 8)} · {row.progress}%
                              </small>
                            )}
                          </button>
                        ) : column.key === "state" ||
                          column.key === "status" ||
                          column.key === "activity_type" ||
                          (page === "releases" && column.label === "State") ? (
                          <Badge
                            value={
                              row.state ||
                              row.status ||
                              row.activity_type ||
                              "Released"
                            }
                          />
                        ) : column.key === "owner_user.email" ? (
                          <span className="owner-name">
                            {row.owner_user?.first_name ||
                              row.owner_user?.email ||
                              "Unassigned"}
                          </span>
                        ) : column.key === timestampKeys[page] ? (
                          <time title={row[column.key]}>
                            {date(
                              row[column.key] ||
                                row.date_created ||
                                row.created_at,
                            )}
                          </time>
                        ) : column.type === "tags" ? (
                          <div className="tag-list">
                            {row.tags?.slice(0, 3).map((tag: any) => (
                              <button
                                className="tag"
                                key={tag.text || tag}
                                onClick={() => quick("tags", tag.text || tag)}
                              >
                                {tag.text || tag}
                              </button>
                            ))}
                            {row.tags?.length > 3 && (
                              <span>+{row.tags.length - 3}</span>
                            )}
                          </div>
                        ) : column.type === "metadata" ? (
                          String(
                            row.metadata_values?.[column.field]?.value ?? "—",
                          )
                        ) : (
                          String(row[column.key] ?? "—")
                        )}
                      </td>
                    ))}
                    <td className="row-actions">
                      <button
                        aria-label={"Open " + (row[nameKeys[page]] || row.id)}
                        onClick={() => open(row)}
                      >
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.data.length && (
              <Empty text="No records match these filters." />
            )}
          </div>
        )}
        <div className="pagination">
          <span>
            {total
              ? fmt(index * size + 1) +
                "–" +
                fmt(Math.min((index + 1) * size, total))
              : "0"}{" "}
            of {fmt(total)}
            {loading ? " · Updating…" : ""}
          </span>
          <div>
            <label>
              Rows
              <select
                aria-label="Rows per page"
                value={size}
                onChange={(e) => {
                  setSize(Number(e.target.value));
                  setIndex(0);
                }}
              >
                {[25, 50, 100, 200].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <IconButton
              label="Previous page"
              disabled={index === 0 || loading}
              onClick={() => setIndex(Math.max(0, index - 1))}
            >
              <ChevronLeft size={16} />
            </IconButton>
            <label>
              Page
              <input
                aria-label="Page number"
                type="number"
                min={1}
                max={pages}
                value={index + 1}
                onChange={(e) => {
                  const value = Number(e.target.value);
                  if (value >= 1 && value <= pages) setIndex(value - 1);
                }}
              />
            </label>
            <span>of {fmt(pages)}</span>
            <IconButton
              label="Next page"
              disabled={index + 1 >= pages || loading}
              onClick={() => setIndex(index + 1)}
            >
              <ChevronRight size={16} />
            </IconButton>
          </div>
        </div>
      </section>
      {editable &&
        user?.admin &&
        view === "Inactive Only" &&
        page !== "tasks" && (
          <div className="danger-zone">
            <button
              className="text-danger"
              onClick={async () => {
                if (
                  !confirm(
                    "Permanently delete all inactive " +
                      entityNames[page] +
                      " records? This cannot be undone.",
                  )
                )
                  return;
                try {
                  await write(
                    "/" +
                      (page === "c2ips" ? "c2ip" : page) +
                      "/delete_all_inactive",
                    {},
                    "PUT",
                  );
                  refresh();
                  notify("Inactive records deleted.");
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Permanently delete inactive records
            </button>
          </div>
        )}
      {editor && (
        <ArtifactEditor
          user={user}
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
      {bulk && (
        <BulkEditor
          count={selected.size}
          ids={[...selected]}
          page={page}
          states={states}
          users={users}
          categories={categories}
          notify={notify}
          onClose={() => setBulk(false)}
          onSaved={() => {
            setBulk(false);
            setSelected(new Set());
            refresh();
          }}
        />
      )}
      {source && (
        <Dialog
          wide
          title={source.merged ? "Merged signature" : "YARA source"}
          onClose={() => setSource(null)}
        >
          <div className="dialog-body">
            <label>
              YARA source
              <textarea
                aria-label="YARA source"
                className="code-input source-editor"
                readOnly
                value={source.text}
              />
            </label>
          </div>
          <div className="dialog-footer">
            <button onClick={() => downloadText(source.text, "signatures.yar")}>
              Download YARA
            </button>
            <button
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(source.text);
                  notify("YARA copied.");
                } catch {
                  notify("Copy is unavailable. Select the source text.", true);
                }
              }}
            >
              Copy YARA
            </button>
            {source.merged && (
              <button
                className="primary"
                onClick={async () => {
                  try {
                    await write("/import", {
                      import_text: source.text,
                      autocommit: true,
                      shared_state: "Vetting",
                      extract_ip: false,
                      extract_dns: false,
                    });
                    setSource(null);
                    refresh();
                    notify("Merged draft imported.");
                  } catch (e: any) {
                    notify(e.message, true);
                  }
                }}
              >
                Import merged draft
              </button>
            )}
          </div>
        </Dialog>
      )}
      {extra && (
        <Dialog
          wide
          title={extra.name || extra.kind || "Activity details"}
          onClose={() => setExtra(null)}
        >
          <div className="dialog-body">
            <dl className="detail-list">
              {Object.entries(extra)
                .filter(([key]) => !["result", "payload"].includes(key))
                .map(([key, value]) => (
                  <div key={key}>
                    <dt>{key.replaceAll("_", " ")}</dt>
                    <dd>
                      {typeof value === "object"
                        ? JSON.stringify(value)
                        : String(value ?? "—")}
                    </dd>
                  </div>
                ))}
            </dl>
            {extra.result && (
              <pre className="source-preview">
                {JSON.stringify(extra.result, null, 2)}
              </pre>
            )}
          </div>
          {page === "releases" && (
            <div className="dialog-footer">
              <button
                className="text-danger"
                onClick={async () => {
                  if (!confirm("Delete this release?")) return;
                  try {
                    await api("/releases/" + extra.id, { method: "DELETE" });
                    setExtra(null);
                    refresh();
                    notify("Release deleted.");
                  } catch (e: any) {
                    notify(e.message, true);
                  }
                }}
              >
                Delete release
              </button>
              <a
                className="button"
                href={base + "/releases/" + extra.id + "/release_notes"}
              >
                Download notes
              </a>
              <a
                className="button"
                href={base + "/releases/" + extra.id + "/artifact_export"}
              >
                Download release
              </a>
            </div>
          )}
        </Dialog>
      )}
    </>
  );
}

function BulkEditor({
  count,
  ids,
  page,
  states,
  users,
  categories,
  notify,
  onClose,
  onSaved,
}: any) {
  const [state, setState] = useState(""),
    [owner, setOwner] = useState("unchanged"),
    [category, setCategory] = useState(""),
    [tags, setTags] = useState(""),
    [description, setDescription] = useState(""),
    [replace, setReplace] = useState(false),
    [busy, setBusy] = useState(false);
  return (
    <Dialog
      title={"Edit " + count + " records"}
      onClose={onClose}
      dirty={!!(state || owner !== "unchanged" || category || tags || replace)}
      busy={busy}
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          const batch: any = { ids };
          if (state) batch.state = state;
          if (owner !== "unchanged")
            batch.owner_user =
              owner === "unassigned" ? null : { id: Number(owner) };
          if (category) batch.category = category;
          if (tags.trim())
            batch.tags = tags
              .split(",")
              .map((value) => value.trim())
              .filter(Boolean);
          if (replace) batch.description = description;
          try {
            await write("/" + page + "/batch/edit", { batch }, "PUT");
            onSaved();
            notify("Selected records updated.");
          } catch (error: any) {
            notify(error.message, true);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="dialog-body form-grid">
          <label>
            State
            <select
              aria-label="State"
              value={state}
              onChange={(e) => setState(e.target.value)}
            >
              <option value="">Keep existing</option>
              {states.map((row: any) => (
                <option key={row.id}>{row.state}</option>
              ))}
            </select>
          </label>
          <label>
            Owner
            <select
              aria-label="Owner"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
            >
              <option value="unchanged">Keep existing</option>
              <option value="unassigned">Unassigned</option>
              {users
                .filter((row: any) => row.active)
                .map((row: any) => (
                  <option key={row.id} value={row.id}>
                    {row.email}
                  </option>
                ))}
            </select>
          </label>
          {page === "yara_rules" && (
            <label className="span2">
              Category
              <select
                aria-label="Category"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
              >
                <option value="">Keep existing</option>
                {categories.map((row: any) => (
                  <option key={row.id}>{row.category}</option>
                ))}
              </select>
            </label>
          )}
          <label className="span2">
            Add tags
            <input
              aria-label="Add tags"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="Comma separated"
            />
          </label>
          <label className="span2 check-label">
            <input
              type="checkbox"
              checked={replace}
              onChange={(e) => setReplace(e.target.checked)}
            />
            Replace description
          </label>
          {replace && (
            <label className="span2">
              Description
              <textarea
                aria-label="Description"
                rows={4}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </label>
          )}
        </div>
        <div className="dialog-footer">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "Saving…" : "Apply changes"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
function ActivityDistribution({ days }: any) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    api("/activity_log/distribution?since=" + days).then(setData);
  }, [days]);
  if (!data) return null;
  return (
    <details className="panel activity-distribution">
      <summary>Activity by analyst · {fmt(data.total)} changes</summary>
      <div className="distribution-list">
        {data.users.map((user: any) => (
          <div key={user.id || "system"}>
            <span>{user.email}</span>
            <progress max={100} value={user.percent} />
            <span>
              {user.count} · {user.percent}%
            </span>
          </div>
        ))}
      </div>
    </details>
  );
}
