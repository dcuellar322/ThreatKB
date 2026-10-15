import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { fmt, date } from "../lib/format";
import { Badge, Loading, Empty } from "./ui";
export function Dashboard({ version, go }: any) {
  const [data, setData] = useState<any>(null),
    [releaseVersion, setReleaseVersion] = useState<any>(null);
  useEffect(() => {
    api("/dashboard").then(setData);
    api("/version").then(setReleaseVersion);
  }, [version]);
  if (!data) return <Loading />;
  return (
    <>
      <div className="metric-grid">
        {[
          ["signatures", "Signatures", "yara_rules"],
          ["ips", "IP indicators", "c2ips"],
          ["domains", "Domain indicators", "c2dns"],
          ["tasks", "Tasks", "tasks"],
        ].map(([key, label, page]) => (
          <button key={key} className="metric-card" onClick={() => go(page)}>
            <span>{label}</span>
            <strong>{fmt(data.counts[key])}</strong>
          </button>
        ))}
      </div>
      <section className="panel">
        <div className="section-top">
          <h2>Signature workflow</h2>
          <button onClick={() => go("content")}>Detection as code</button>
        </div>
        <div className="workflow-counts">
          {data.states.map((row: any) => (
            <div key={row.state}>
              <Badge value={row.state} />
              <strong>{fmt(row.count)}</strong>
            </div>
          ))}
        </div>
      </section>
      <div className="overview-summaries">
        <section className="panel">
          <div className="section-top">
            <h2>Artifact ownership</h2>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {["Owner", "Signatures", "IPs", "Domains", "Tasks"].map(
                    (name) => (
                      <th key={name}>{name}</th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {data.ownership?.map((row: any) => (
                  <tr key={row.email}>
                    <td>{row.email}</td>
                    {["signatures", "ips", "domains", "tasks"].map((key) => (
                      <td key={key}>{fmt(row.counts[key])}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <section className="panel">
          <div className="section-top">
            <h2>Signature categories</h2>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Signatures</th>
                </tr>
              </thead>
              <tbody>
                {data.categories?.map((row: any) => (
                  <tr key={row.category}>
                    <td>{row.category}</td>
                    <td>{fmt(row.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
      {!!data.releases?.length && (
        <section className="panel">
          <div className="section-top">
            <h2>Latest production releases</h2>
            <a className="button" href="#/releases">
              All releases
            </a>
          </div>
          {data.releases.map((row: any) => (
            <article className="activity-row" key={row.id}>
              <strong>{row.name}</strong>
              <time>{date(row.date_created)}</time>
            </article>
          ))}
        </section>
      )}
      <section className="panel">
        <div className="section-top">
          <h2>Recent activity</h2>
          <button onClick={() => go("activity_log")}>All activity</button>
        </div>
        {data.activity.length ? (
          data.activity.map((row: any) => (
            <article className="activity-row" key={row.id}>
              <div>
                <strong>{row.activity_text}</strong>
                <small>
                  {row.user?.email || "System"} · {row.entity_type}
                </small>
              </div>
              <Badge value={row.activity_type} />
              <time>{date(row.activity_date)}</time>
            </article>
          ))
        ) : (
          <Empty />
        )}
      </section>
      {releaseVersion?.version && releaseVersion.version !== "unavailable" && (
        <small className="muted">ThreatKB {releaseVersion.version}</small>
      )}
    </>
  );
}
