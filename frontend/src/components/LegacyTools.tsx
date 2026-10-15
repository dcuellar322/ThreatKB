import { useEffect, useState } from "react";
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Download,
  Eye,
  Search,
  Trash2,
} from "lucide-react";
import { api, base } from "../lib/api";
import { date } from "../lib/format";
import { recordLink } from "../lib/links";
import { Badge, Dialog, Empty, IconButton, Loading } from "./ui";
import { Select } from "./Select";
import { UploadFiles } from "./UploadFiles";
import { ErrorDetails } from "./ErrorDetails";

export function LegacyTools({ page, version, notify, user }: any) {
  const [rows, setRows] = useState<any[] | null>(null),
    [query, setQuery] = useState(""),
    [index, setIndex] = useState(0),
    [size, setSize] = useState(25),
    [total, setTotal] = useState(0),
    [sort, setSort] = useState(
      page === "tests"
        ? "start_time"
        : page === "files"
          ? "filename"
          : "date_created",
    ),
    [direction, setDirection] = useState("DESC"),
    [detail, setDetail] = useState<any>(null),
    [revision, setRevision] = useState(0),
    [error, setError] = useState("");
  const reload = () => setRevision((v) => v + 1);
  useEffect(() => {
    if (page !== "tests") return;
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") reload();
    }, 5000);
    return () => clearInterval(timer);
  }, [page]);
  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      const params = new URLSearchParams({
        page_number: String(index),
        page_size: String(size),
        sort_by: sort,
        sort_dir: direction,
        searches: JSON.stringify(query ? { yara_rule_name: query } : {}),
      });
      api("/" + page + (page === "tests" ? "?" + params : ""), {
        signal: controller.signal,
      })
        .then((r) => {
          setRows(page === "tests" ? r.data : r);
          setTotal(page === "tests" ? r.total_count : r.length);
          setError("");
        })
        .catch((e) => {
          if (e.name !== "AbortError") setError(e.message);
        });
    }, 200);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [
    page,
    version,
    revision,
    index,
    size,
    sort,
    direction,
    page === "tests" ? query : "",
  ]);
  const filtered = (rows || []).filter(
    (r) =>
      page === "tests" ||
      [
        r.filename,
        r.content_type,
        r.sha256,
        r.route,
        r.method,
        r.user?.email,
        r.stacktrace,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  if (page !== "tests")
    filtered.sort(
      (a, b) =>
        String(a[sort] ?? "").localeCompare(String(b[sort] ?? ""), undefined, {
          numeric: true,
        }) * (direction === "ASC" ? 1 : -1),
    );
  const count = page === "tests" ? total : filtered.length;
  useEffect(() => {
    setIndex((current) =>
      Math.min(current, Math.max(0, Math.ceil(count / size) - 1)),
    );
  }, [count, size]);
  const visible =
    page === "tests"
      ? filtered
      : filtered.slice(index * size, (index + 1) * size);
  const columns =
    page === "tests"
      ? [
          ["yara_rule_name", "Signature"],
          ["revision", "Revision"],
          ["test_type", "Type"],
          ["status", "Status"],
          ["files_tested", "Tested"],
          ["files_matched", "Matched"],
          ["start_time", "Started"],
        ]
      : page === "files"
        ? [
            ["filename", "Filename"],
            ["content_type", "Content type"],
            ["sha256", "SHA-256"],
            ["date_modified", "Updated"],
          ]
        : [
            ["route", "Route"],
            ["method", "Method"],
            ["date_created", "Date"],
            ["remote_addr", "Address"],
          ];
  return (
    <>
      <section className="panel records-panel">
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={16} />
            <input
              aria-label={"Search " + page}
              placeholder={
                page === "tests" ? "Search signatures" : "Search " + page
              }
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setIndex(0);
              }}
            />
          </div>
          {page === "files" && (
            <UploadFiles notify={notify} onUploaded={reload} />
          )}
          {page === "errors" && <span className="muted">Latest 50 errors</span>}
        </div>
        {error && (
          <p className="banner danger" role="alert">
            {error}
          </p>
        )}
        {!rows ? (
          <Loading />
        ) : (
          <div className="table-scroll">
            <table className="records-table">
              <thead>
                <tr>
                  {columns.map(([key, label]) => (
                    <th
                      key={key}
                      aria-sort={
                        sort === key
                          ? direction === "ASC"
                            ? "ascending"
                            : "descending"
                          : undefined
                      }
                    >
                      <button
                        className="sort-button"
                        aria-label={"Sort by " + label}
                        onClick={() => {
                          setSort(key);
                          setDirection(
                            sort === key && direction === "DESC"
                              ? "ASC"
                              : "DESC",
                          );
                          setIndex(0);
                        }}
                      >
                        {label}
                        <ArrowUpDown size={13} />
                      </button>
                    </th>
                  ))}
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {visible.map((row) => (
                  <tr key={row.id}>
                    {columns.map(([key], i) => (
                      <td key={key}>
                        {i === 0 ? (
                          page === "files" ? (
                            <a
                              className="record-name"
                              href={base + "/files/" + row.id}
                              download
                            >
                              {row[key]}
                            </a>
                          ) : (
                            <button
                              className="record-name"
                              onClick={async () => {
                                try {
                                  setDetail(
                                    await api("/" + page + "/" + row.id),
                                  );
                                } catch (e: any) {
                                  notify(e.message, true);
                                }
                              }}
                            >
                              {row[key]}
                            </button>
                          )
                        ) : key === "status" ? (
                          <Badge value={row[key]} />
                        ) : key.includes("time") || key.startsWith("date_") ? (
                          date(row[key])
                        ) : (
                          <span
                            title={String(row[key] || "")}
                            className={key === "sha256" ? "hash-value" : ""}
                          >
                            {row[key] ?? "—"}
                          </span>
                        )}
                      </td>
                    ))}
                    <td className="row-actions">
                      {page === "files" ? (
                        <div className="button-row">
                          <a
                            className="button icon-button"
                            aria-label={"Download " + row.filename}
                            href={base + "/files/" + row.id}
                            download
                          >
                            <Download size={15} />
                          </a>
                          {user.admin && (
                            <IconButton
                              label={"Delete " + row.filename}
                              onClick={async () => {
                                if (!confirm("Delete " + row.filename + "?"))
                                  return;
                                try {
                                  await api("/files/" + row.id, {
                                    method: "DELETE",
                                  });
                                  reload();
                                  notify("File deleted.");
                                } catch (e: any) {
                                  notify(e.message, true);
                                }
                              }}
                            >
                              <Trash2 size={15} />
                            </IconButton>
                          )}
                        </div>
                      ) : (
                        <IconButton
                          label={`View ${page === "errors" ? "error" : "test"} ${row.id} details`}
                          onClick={async () => {
                            try {
                              setDetail(await api("/" + page + "/" + row.id));
                            } catch (e: any) {
                              notify(e.message, true);
                            }
                          }}
                        >
                          <Eye size={16} />
                        </IconButton>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!visible.length && <Empty />}
          </div>
        )}
        <div className="pagination">
          <span>
            {count ? index * size + 1 : 0}–{Math.min((index + 1) * size, count)}{" "}
            of {count}
          </span>
          <div className="button-row">
            <label className="check-label">
              Rows
              <Select
                aria-label="Rows per page"
                value={size}
                onChange={(e: any) => {
                  setSize(Number(e.target.value));
                  setIndex(0);
                }}
              >
                {[25, 50, 100, 200].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            </label>
            <IconButton
              label="Previous page"
              disabled={!index}
              onClick={() => setIndex(index - 1)}
            >
              <ChevronLeft size={16} />
            </IconButton>
            <span>
              {index + 1} / {Math.max(1, Math.ceil(count / size))}
            </span>
            <IconButton
              label="Next page"
              disabled={(index + 1) * size >= count}
              onClick={() => setIndex(index + 1)}
            >
              <ChevronRight size={16} />
            </IconButton>
          </div>
        </div>
      </section>
      {detail && (
        <Dialog
          wide
          title={
            page === "tests"
              ? detail.yara_rule_name + " · Revision " + detail.revision
              : detail.method + " " + detail.route
          }
          onClose={() => setDetail(null)}
        >
          <div className="dialog-body">
            {page === "tests" ? (
              <>
                <div className="section-top">
                  <span>
                    {detail.test_type} · {detail.files_matched || 0} matched /{" "}
                    {detail.files_tested || 0} tested
                  </span>
                  <a
                    className="button"
                    href={recordLink("yara_rules", detail.yara_rule_id)}
                  >
                    Open signature
                  </a>
                </div>
                <div
                  className="table-scroll test-results"
                  role="region"
                  aria-label="File test results"
                  tabIndex={0}
                >
                  <table>
                    <thead>
                      <tr>
                        {[
                          "Path",
                          "Matched",
                          "Command",
                          "Match regex",
                          "Output",
                          "Errors",
                          "Run time",
                        ].map((t) => (
                          <th key={t}>{t}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {detail.file_matches?.map((r: any) => (
                        <tr key={r.id}>
                          <td>{r.path}</td>
                          <td>{r.matched ? "Yes" : "No"}</td>
                          <td>
                            <pre>{r.command}</pre>
                          </td>
                          <td>{r.command_match_test_regex}</td>
                          <td>
                            <pre>{r.stdout}</pre>
                          </td>
                          <td>
                            <pre>{r.stderr}</pre>
                          </td>
                          <td>{r.run_time}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!detail.file_matches?.length && (
                    <Empty text="No file results." />
                  )}
                </div>
              </>
            ) : (
              <ErrorDetails error={detail} notify={notify} />
            )}
          </div>
          <div className="dialog-footer">
            <button onClick={() => setDetail(null)}>Close</button>
          </div>
        </Dialog>
      )}
    </>
  );
}
