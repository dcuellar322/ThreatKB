export const base = "/ThreatKB";
export async function api(path: string, options: any = {}) {
  const r = await fetch(base + path, {
    credentials: "same-origin",
    ...options,
    headers:
      options.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json", ...options.headers },
  });
  const text = await r.text();
  let value: any;
  try {
    value = text ? JSON.parse(text) : null;
  } catch {
    value = text;
  }
  if (r.status === 401 && path !== "/login" && path !== "/users/me")
    window.dispatchEvent(new Event("threatkb:unauthorized"));
  if (!r.ok)
    throw new Error(
      typeof value === "object"
        ? value?.error || value?.message || `Request failed (${r.status})`
        : value || `Request failed (${r.status})`,
    );
  return value;
}
export const write = (path: string, data: any, method = "POST") =>
  api(path, { method, body: JSON.stringify(data) });
