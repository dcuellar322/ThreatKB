import { useState, useEffect } from "react";
import { Bell } from "lucide-react";
import { api, write } from "../lib/api";
import { date } from "../lib/format";

import { Empty } from "./ui";
export function Account({ user, notify }: any) {
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
              aria-label="New password"
              type="password"
              autoComplete="new-password"
              minLength={1}
              maxLength={72}
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
              aria-label="New secret (shown once)"
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
              disabled={key.status === "deleted"}
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
              disabled={key.status === "deleted"}
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
export function Following({ notify }: any) {
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
