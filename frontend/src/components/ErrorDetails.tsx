import { useEffect, useId, useState } from "react";
import { AlertCircle, Check, Copy } from "lucide-react";
import { date } from "../lib/format";
import { IconButton } from "./ui";

function argumentsText(value: any) {
  if (value == null || value === "") return "—";
  try {
    return JSON.stringify(
      typeof value === "string" ? JSON.parse(value) : value,
      null,
      2,
    );
  } catch {
    return String(value);
  }
}

export function ErrorDetails({ error }: any) {
  const heading = useId();
  const [copyState, setCopyState] = useState("idle");
  useEffect(() => {
    if (copyState !== "copied") return;
    const timer = setTimeout(() => setCopyState("idle"), 2000);
    return () => clearTimeout(timer);
  }, [copyState]);
  const traceback = error.stacktrace || "";
  const summary = traceback
    .trim()
    .split(/\r?\n/)
    .reverse()
    .find((line: string) => /^[A-Za-z_][\w.]*(?::|$)/.test(line));
  const args = argumentsText(error.args);
  const report = [
    `${error.method} ${error.route}`,
    `Error ID: ${error.id}`,
    `Date: ${error.date_created}`,
    `User: ${error.user?.email || "—"}`,
    `Address: ${error.remote_addr || "—"}`,
    "",
    "Request arguments:",
    args,
    "",
    "Traceback:",
    traceback,
  ].join("\n");
  return (
    <div className="error-details">
      {summary && (
        <p className="error-summary">
          <AlertCircle size={18} aria-hidden="true" />
          <code>{summary}</code>
        </p>
      )}
      <dl className="error-context">
        <div>
          <dt>Recorded</dt>
          <dd>
            <time dateTime={error.date_created}>
              {date(error.date_created)}
            </time>
          </dd>
        </div>
        <div>
          <dt>User</dt>
          <dd>{error.user?.email || "—"}</dd>
        </div>
        <div>
          <dt>Address</dt>
          <dd>
            <code>{error.remote_addr || "—"}</code>
          </dd>
        </div>
        <div>
          <dt>Error ID</dt>
          <dd>{error.id}</dd>
        </div>
      </dl>
      <details className="disclosure error-arguments">
        <summary>Request arguments</summary>
        <pre>{args}</pre>
      </details>
      <section className="error-trace-panel">
        <div className="error-trace-toolbar">
          <h3 id={heading}>Traceback</h3>
          <div className="error-copy-action">
            <span className="muted" role="status">
              {copyState === "copied" ? "Copied" : ""}
            </span>
            <IconButton
              label="Copy error report"
              title={copyState === "copied" ? "Copied" : "Copy error report"}
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(report);
                  setCopyState("copied");
                } catch {
                  setCopyState("failed");
                }
              }}
            >
              {copyState === "copied" ? (
                <Check size={16} />
              ) : (
                <Copy size={16} />
              )}
            </IconButton>
          </div>
        </div>
        {copyState === "failed" && (
          <p className="error-copy-failure" role="alert">
            Could not copy the report. Select the traceback to copy it manually.
          </p>
        )}
        <pre
          className="error-trace"
          role="region"
          aria-labelledby={heading}
          tabIndex={0}
        >
          {traceback || "No traceback recorded."}
        </pre>
      </section>
    </div>
  );
}
