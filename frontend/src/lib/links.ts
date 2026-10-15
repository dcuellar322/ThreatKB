const aliases: Record<string, string> = {
  profile: "account",
  access_keys: "account",
  tests: "tests",
  files: "files",
  errors: "errors",
  metadata: "settings?tab=Metadata",
  tags: "settings?tab=Tags",
  macros: "settings?tab=Macros",
  users: "settings?tab=Users",
  cfg_settings: "settings?tab=Settings",
  cfg_states: "settings?tab=States",
  cfg_category_range_mapping: "settings?tab=Categories",
  whitelist: "whitelist",
  scripts: "settings?tab=Scripts",
  "scripts/run": "settings?tab=Scripts",
  import: "import",
};
export function normalizeHash(hash: string) {
  const route = hash.replace(/^#!?\/?/, "");
  if (!route) return "#/yara_rules";
  if (route === "main-content") return "#/yara_rules";
  const record = route.match(/^(yara_rules|c2ips|c2dns|tasks)\/(\d+|add)$/);
  if (record)
    return (
      "#/" +
      record[1] +
      "?" +
      (record[2] === "add" ? "new=1" : "id=" + record[2])
    );
  return "#/" + (aliases[route] || route);
}
export function recordLink(page: string, id: number | string) {
  return "#/" + page + "?id=" + encodeURIComponent(id);
}
export function permalink(page: string, id: number | string) {
  const url = new URL(location.href);
  url.hash = recordLink(page, id);
  return url.href;
}
