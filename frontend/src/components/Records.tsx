import { flushSync } from "react-dom";
import { TagInput, RecordTags } from "./TagInput";
import { recordLink } from "../lib/links";
import { Select } from "./Select";
import { useState, useEffect, useRef } from "react";
import {
  Search,
  Plus,
  ChevronLeft,
  ChevronRight,
  ArrowUpRight,
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
import { Badge, IconButton, Empty, Dialog, Loading, DetailList } from "./ui";
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
    [savingRow, setSavingRow] = useState<number | null>(null),
    [bulk, setBulk] = useState<number[] | null>(null),
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
  const allRef = useRef<HTMLInputElement>(null),
    columnMenuRef = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    if (!showColumns) return;
    const outside = (e: PointerEvent) => {
      if (!columnMenuRef.current?.contains(e.target as Node))
        setShowColumns(false);
    };
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setShowColumns(false);
        columnMenuRef.current?.querySelector("summary")?.focus();
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", escape);
    };
  }, [showColumns]);
  const editable = !!kinds[page];
  useEffect(() => {
    if (query === debounced) return;
    const timer = setTimeout(() => {
      setDebounced(query);
      setIndex(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [query, debounced]);
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
  }, [page, index, size, query, debounced, view, filters, operator, sort, direction]);
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
  const newRecord = new URLSearchParams(location.hash.split("?")[1] || "").has(
    "new",
  );
  const recordId = new URLSearchParams(location.hash.split("?")[1] || "").get(
    "id",
  );
  useEffect(() => {
    const id = recordId;
    const controller = new AbortController();
    if (id && editable) {
      setEditor(null);
      api("/" + page + "/" + id, { signal: controller.signal })
        .then((value) => {
          if (!controller.signal.aborted) setEditor(value);
        })
        .catch((e: any) => {
          if (e.name !== "AbortError") notify(e.message, true);
        });
    } else if (newRecord) setEditor({ new: true, tags: [] });
    else setEditor(null);
    return () => controller.abort();
  }, [page, recordId, newRecord]);
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
      if (editable) location.hash = recordLink(page, row.id);
      else setExtra(row);
    } catch (e: any) {
      notify(e.message, true);
    }
  };
  const closeEditor = () => {
    // Remove the dialog guard before navigating after a successful save or close.
    flushSync(() => setEditor(null));
    if (recordId || location.hash.includes("new=")) location.hash = "#/" + page;
  };
  const quickEdit = async (row: any, field: string, value: any) => {
    setSavingRow(row.id);
    try {
      const record = await api("/" + page + "/" + row.id);
      await write(
        "/" + page + "/" + row.id,
        { ...record, [field]: value, do_not_bump_revision: true },
        "PUT",
      );
      refresh();
      notify("Record updated.");
    } catch (e: any) {
      notify(e.message, true);
    } finally {
      setSavingRow(null);
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
              ? "is_test_release"
              : "state",
      label:
        page === "jobs"
          ? "Status"
          : page === "activity_log"
            ? "Action"
            : page === "releases"
              ? "Channel"
              : "State",
    },
    ...(page === "releases"
      ? [
          { key: "num_signatures", label: "Signatures" },
          { key: "num_ips", label: "IPs" },
          { key: "num_dns", label: "Domains" },
          { key: null, label: "Created by", type: "creator" },
        ]
      : []),
    ...(page === "activity_log"
      ? [{ key: "user.email", label: "Analyst", type: "analyst" }]
      : []),
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
      ? [
          {
            key: timestampKeys[page],
            label: page === "releases" ? "Created" : "Updated",
          },
        ]
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
  const pending = loading || query !== debounced;
  const total = data?.total_count || 0,
    pages = Math.max(1, Math.ceil(total / size));
  return (
    <>
      {page === "activity_log" && <ActivityDistribution days={days} />}
      <section className="panel records-panel" aria-busy={pending}>
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
              <Select
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
              </Select>
            )}
            {editable && (
              <>
                <Select
                  aria-label="Filter by state"
                  value={filters.find((f) => f.field === "state")?.value || ""}
                  onChange={(e) => quick("state", e.target.value)}
                >
                  <option value="">All states</option>
                  {states.map((state) => (
                    <option key={state.id}>{state.state}</option>
                  ))}
                </Select>
                <Select
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
                </Select>
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
              ref={columnMenuRef}
              className="column-menu"
              open={showColumns}
              onToggle={(e) => setShowColumns(e.currentTarget.open)}
            >
              <summary>Columns</summary>
              <div>
                {[
                  ...(editable
                    ? [
                        ["owner", "Owner"],
                        ["tags", "Tags"],
                      ]
                    : []),
                  ...(page === "yara_rules" ? [["category", "Category"]] : []),
                  ["updated", page === "releases" ? "Created" : "Updated"],
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
              <Select
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
              </Select>
            </label>
            <label>
              Match
              <Select
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
              </Select>
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
          <fieldset className="selection-bar" disabled={pending}>
            <strong>{selected.size} selected</strong>
            <button onClick={() => setBulk([...selected])}>
              Edit selected
            </button>
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
          </fieldset>
        )}
        {error ? (
          <div className="inline-error" role="alert">
            {error}
            <button onClick={refresh}>Retry</button>
          </div>
        ) : !data ? (
          <Loading />
        ) : (
          <div
            className="table-scroll"
            role="region"
            aria-label="Record table"
            tabIndex={0}
          >
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
                        disabled={pending || !data.data.length}
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
                          disabled={pending}
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
                          <a
                            className="record-name"
                            href={
                              editable ? recordLink(page, row.id) : "#/" + page
                            }
                            aria-disabled={loading || undefined}
                            title={row.uuid || String(row.id)}
                            onClick={(e) => {
                              if (loading) {
                                e.preventDefault();
                                return;
                              }
                              if (!editable) {
                                e.preventDefault();
                                open(row);
                              }
                            }}
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
                          </a>
                        ) : column.key === "state" && editable ? (
                          <Select
                            className="cell-select state-select"
                            renderValue={(label: string) => (
                              <Badge value={label} />
                            )}
                            aria-label={"State for " + row[nameKeys[page]]}
                            value={row.state || ""}
                            disabled={loading || savingRow === row.id}
                            onChange={(e: any) => {
                              if (e.target.value !== row.state)
                                quickEdit(row, "state", e.target.value);
                            }}
                          >
                            {row.state &&
                              !states.some((s) => s.state === row.state) && (
                                <option>{row.state}</option>
                              )}
                            {states
                              .filter(
                                (s) =>
                                  user.admin ||
                                  !s.is_release_state ||
                                  s.state === row.state,
                              )
                              .map((s) => (
                                <option key={s.id} value={s.state}>
                                  {s.state}
                                </option>
                              ))}
                          </Select>
                        ) : column.key === "is_test_release" ? (
                          <Badge
                            value={
                              row.is_test_release
                                ? "Test release"
                                : "Production"
                            }
                          />
                        ) : column.type === "creator" ? (
                          row.created_user?.email || "System"
                        ) : column.type === "analyst" ? (
                          row.user?.email || "System"
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
                          <Select
                            className="cell-select owner-select"
                            aria-label={"Owner for " + row[nameKeys[page]]}
                            value={row.owner_user?.id || ""}
                            disabled={loading || savingRow === row.id}
                            onChange={(e: any) => {
                              if (
                                String(e.target.value) !==
                                String(row.owner_user?.id || "")
                              )
                                quickEdit(
                                  row,
                                  "owner_user",
                                  e.target.value
                                    ? { id: Number(e.target.value) }
                                    : null,
                                );
                            }}
                          >
                            <option value="">Unassigned</option>
                            {users
                              .filter((u: any) => u.id)
                              .map((u: any) => (
                                <option key={u.id} value={u.id}>
                                  {u.email}
                                </option>
                              ))}
                          </Select>
                        ) : column.key === timestampKeys[page] ? (
                          <time title={row[column.key]}>
                            {date(
                              row[column.key] ||
                                row.date_created ||
                                row.created_at,
                            )}
                          </time>
                        ) : column.type === "tags" ? (
                          <RecordTags
                            tags={row.tags || []}
                            onFilter={(tag: string) => quick("tags", tag)}
                          />
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
                        disabled={loading}
                      >
                        <ArrowUpRight size={14} aria-hidden="true" />
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
            {pending ? " · Updating…" : ""}
          </span>
          <div>
            <label>
              Rows
              <Select
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
              </Select>
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
          key={editor.id || "new"}
          user={user}
          page={page}
          initial={editor}
          notify={notify}
          onClose={closeEditor}
          onSaved={() => {
            closeEditor();
            refresh();
          }}
        />
      )}
      {bulk && (
        <BulkEditor
          count={bulk.length}
          ids={bulk}
          page={page}
          states={states.filter((s) => user.admin || !s.is_release_state)}
          users={users}
          categories={categories}
          notify={notify}
          onClose={() => setBulk(null)}
          onSaved={() => {
            setBulk(null);
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
          title={extra.name || extra.kind || "Activity details"}
          onClose={() => setExtra(null)}
        >
          <div className="dialog-body">
            <DetailList
              order={
                page === "jobs"
                  ? [
                      "status",
                      "progress",
                      "kind",
                      "created_at",
                      "started_at",
                      "finished_at",
                      "created_user_id",
                      "error",
                      "id",
                    ]
                  : page === "releases"
                    ? [
                        "name",
                        "is_test_release",
                        "num_signatures",
                        "num_ips",
                        "num_dns",
                        "created_user",
                        "date_created",
                        "id",
                      ]
                    : ["activity_text", "user", "activity_date"]
              }
              value={Object.fromEntries(
                Object.entries(extra).filter(
                  ([key]) => !["result", "payload"].includes(key),
                ),
              )}
            />
            {extra.result && (
              <section className="detail-section">
                <h3>Result</h3>
                {typeof extra.result === "object" &&
                !Array.isArray(extra.result) ? (
                  <DetailList value={extra.result} />
                ) : (
                  <pre className="source-preview">
                    {JSON.stringify(extra.result, null, 2)}
                  </pre>
                )}
              </section>
            )}
            {extra.payload && (
              <details className="disclosure">
                <summary>Job inputs</summary>
                <pre className="source-preview">
                  {JSON.stringify(extra.payload, null, 2)}
                </pre>
              </details>
            )}
          </div>
          <div
            className={
              "dialog-footer" + (page === "releases" ? " release-footer" : "")
            }
          >
            {page === "releases" && (
              <>
                <button
                  className="text-danger dialog-danger"
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
              </>
            )}
            <button onClick={() => setExtra(null)}>Close</button>
          </div>
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
  const close = () => {
    if (
      !busy &&
      (!(state || owner !== "unchanged" || category || tags || replace) ||
        confirm("Discard unsaved changes?"))
    )
      onClose();
  };
  return (
    <Dialog
      title={"Edit " + count + (count === 1 ? " record" : " records")}
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
            <Select
              aria-label="State"
              value={state}
              onChange={(e) => setState(e.target.value)}
            >
              <option value="">Keep existing</option>
              {states.map((row: any) => (
                <option key={row.id}>{row.state}</option>
              ))}
            </Select>
          </label>
          <label>
            Owner
            <Select
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
            </Select>
          </label>
          {page === "yara_rules" && (
            <label className="span2">
              Category
              <Select
                aria-label="Category"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
              >
                <option value="">Keep existing</option>
                {categories.map((row: any) => (
                  <option key={row.id}>{row.category}</option>
                ))}
              </Select>
            </label>
          )}
          <div className="field span2">
            <span>Add tags</span>
            <TagInput
              label="Add tags"
              value={tags
                .split(",")
                .map((t: string) => t.trim())
                .filter(Boolean)}
              onChange={(next: string[]) => setTags(next.join(","))}
            />
          </div>
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
          <button type="button" onClick={close}>
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
