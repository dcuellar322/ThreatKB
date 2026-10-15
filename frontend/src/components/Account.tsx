import { useState, useEffect, useRef } from "react";
import { Bell, Download, Upload, Save } from "lucide-react";
import { api, base, write } from "../lib/api";
import { date } from "../lib/format";

import { Empty } from "./ui";
export function Account({ user, notify, onUser, version }: any) {
  const pictureInput = useRef<HTMLInputElement>(null);
  const [keys, setKeys] = useState<any[]>([]),
    [secret, setSecret] = useState<any>(null),
    [keyBusy, setKeyBusy] = useState<number | string | null>(null),
    [password, setPassword] = useState(""),
    [profile, setProfile] = useState({
      first_name: user.first_name || "",
      last_name: user.last_name || "",
      email: user.email,
    }),
    [pictureVersion, setPictureVersion] = useState(0);
  const reload = () =>
    api("/access_keys")
      .then(setKeys)
      .catch((e: any) => notify(e.message, true));
  useEffect(() => {
    reload();
  }, [version]);
  async function changeKey(key: any, status: string) {
    if (keyBusy !== null) return;
    if (status === "deleted" && !confirm("Revoke this access key?")) return;
    setKeyBusy(key.id);
    try {
      await write("/access_keys/" + key.id, { status }, "PUT");
      await reload();
    } catch (e: any) {
      notify(e.message, true);
    } finally {
      setKeyBusy(null);
    }
  }
  return (
    <div className="split-panels">
      <section className="panel import-panel">
        <h2>Your profile</h2>
        <div className="profile-picture">
          <img
            src={base + "/users/me/picture?v=" + pictureVersion}
            alt="Profile picture"
          />
          <button type="button" onClick={() => pictureInput.current?.click()}>
            <Upload size={15} />
            Change picture
          </button>
          <input
            ref={pictureInput}
            type="file"
            accept="image/*"
            hidden
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              try {
                const body = new FormData();
                body.append("file", file);
                const response = await fetch(base + "/users/me/picture", {
                  method: "POST",
                  credentials: "include",
                  body,
                });
                if (!response.ok) throw new Error("Could not upload picture.");
                setPictureVersion((v) => v + 1);
                notify("Picture updated.");
              } catch (error: any) {
                notify(error.message, true);
              }
            }}
          />
        </div>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              const saved = await write(
                "/users/" + user.id,
                { ...user, ...profile },
                "PUT",
              );
              onUser(saved);
              notify("Profile updated.");
            } catch (error: any) {
              notify(error.message, true);
            }
          }}
        >
          <div className="profile-fields">
            <label>
              First name
              <input
                aria-label="First name"
                required
                value={profile.first_name}
                onChange={(e) =>
                  setProfile({ ...profile, first_name: e.target.value })
                }
              />
            </label>
            <label>
              Last name
              <input
                aria-label="Last name"
                required
                value={profile.last_name}
                onChange={(e) =>
                  setProfile({ ...profile, last_name: e.target.value })
                }
              />
            </label>
            <label>
              Email address
              <input
                aria-label="Profile email address"
                required
                type="email"
                value={profile.email}
                onChange={(e) =>
                  setProfile({ ...profile, email: e.target.value })
                }
              />
            </label>
          </div>
          <button>
            <Save size={15} />
            Save profile
          </button>
        </form>
        <hr className="section-divider" />
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
          <input
            className="sr-only"
            tabIndex={-1}
            aria-hidden="true"
            name="username"
            autoComplete="username"
            value={user.email}
            readOnly
          />
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
        <div className="section-top">
          <h2>API access keys</h2>
          <a className="button" href={base + "/access_keys/cli"} download>
            <Download size={15} />
            Download CLI
          </a>
        </div>
        <p className="muted">
          Use a Bearer token with the X-ThreatKB-Secret header. Save a new
          secret before closing this view.
        </p>
        <button
          disabled={keyBusy !== null}
          onClick={async () => {
            if (keyBusy !== null) return;
            setKeyBusy("new");
            try {
              setSecret(await write("/access_keys", {}));
              await reload();
            } catch (e: any) {
              notify(e.message, true);
            } finally {
              setKeyBusy(null);
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
              disabled={key.status === "deleted" || keyBusy !== null}
              onClick={() =>
                changeKey(key, key.status === "active" ? "inactive" : "active")
              }
            >
              {key.status === "active" ? "Disable" : "Enable"}
            </button>
            <button
              className="text-danger"
              disabled={key.status === "deleted" || keyBusy !== null}
              onClick={() => changeKey(key, "deleted")}
            >
              Revoke
            </button>
          </article>
        ))}
      </section>
    </div>
  );
}
export function Following({ notify, version }: any) {
  const [items, setItems] = useState<any[]>([]);
  useEffect(() => {
    api("/bookmarks")
      .then(setItems)
      .catch((e: any) => notify(e.message, true));
  }, [version]);
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
