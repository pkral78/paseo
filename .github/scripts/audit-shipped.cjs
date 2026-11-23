// Fails when a package packed into the desktop app matches a high or critical npm advisory.
// `npm audit` alone cannot gate this build: it also counts the website, Expo tooling and test
// runners, none of which reach the DMG.
// Not covered: packages Metro bundles into Resources/app-dist, which keep no package metadata.
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const semver = require("semver");

// Accepted by advisory, so a new advisory against the same package still blocks.
// Remove an entry once upstream upgrades.
const ACCEPTED = {
  "GHSA-r7fv-28h4-cvq7": "markdown-it: fix needs markdown-it 15 (major)",
  "GHSA-22p9-wv53-3rq4": "linkify-it: pulled in by markdown-it 10; same upgrade",
  "GHSA-v245-v573-v5vm": "linkify-it: pulled in by markdown-it 10; same upgrade",
  "GHSA-mrhx-c7xc-m3w5": "zod: 4.6 changes inferred schema types and packages/client stops compiling",
};
const accepted = (advisory) => ACCEPTED[advisory.url.split("/").pop()];
const BLOCKING = new Set(["high", "critical"]);

const appPath = process.argv[2];
if (!appPath) throw new Error("usage: audit-shipped.cjs <path to Paseo.app> [report.md]");
const resources = path.join(appPath, "Contents", "Resources");

const shipped = new Map();
function record(name, version) {
  if (!name || !version) return;
  if (!shipped.has(name)) shipped.set(name, new Set());
  shipped.get(name).add(version);
}

function readAsarPackages(asarPath) {
  const fd = fs.openSync(asarPath, "r");
  const sizes = Buffer.alloc(16);
  fs.readSync(fd, sizes, 0, 16, 0);
  const headerSize = sizes.readUInt32LE(4);
  const header = Buffer.alloc(sizes.readUInt32LE(12));
  fs.readSync(fd, header, 0, header.length, 16);
  const base = 8 + headerSize;
  (function walk(node, dir) {
    for (const [name, entry] of Object.entries(node.files ?? {})) {
      const full = `${dir}/${name}`;
      if (entry.files) walk(entry, full);
      else if (name === "package.json" && !entry.unpacked && /node_modules\/(@[^/]+\/)?[^/]+\/package\.json$/.test(full)) {
        const body = Buffer.alloc(entry.size);
        fs.readSync(fd, body, 0, entry.size, base + Number(entry.offset));
        try {
          const pkg = JSON.parse(body.toString());
          record(pkg.name, pkg.version);
        } catch {}
      }
    }
  })(JSON.parse(header.toString()), "");
  fs.closeSync(fd);
}

function readDiskPackages(dir) {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (entry.name !== "package.json" || !entry.isFile()) continue;
    const file = path.join(entry.parentPath ?? entry.path, entry.name);
    if (!/node_modules\/(@[^/]+\/)?[^/]+\/package\.json$/.test(file)) continue;
    try {
      const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
      record(pkg.name, pkg.version);
    } catch {}
  }
}

readAsarPackages(path.join(resources, "app.asar"));
readDiskPackages(path.join(resources, "app.asar.unpacked"));
if (shipped.size === 0) throw new Error(`No packages found in ${resources}`);
// Electron is the runtime, not a package in the asar.
const electronVersion = require("electron/package.json").version;
record("electron", electronVersion);

// npm audit exits non-zero whenever it finds anything, so only the JSON matters.
const audit = spawnSync("npm", ["audit", "--json"], { encoding: "utf8", maxBuffer: 1 << 28 });
const report = JSON.parse(audit.stdout);
if (!report.vulnerabilities) throw new Error(`npm audit returned no report: ${audit.stdout.slice(0, 400)}`);

// Metro bundles these into Resources/app-dist without package metadata, so the app cannot be
// inspected for them. Their lockfile versions are reported instead and never block.
const WEB_BUNDLE = ["mermaid", "katex", "dompurify", "expo-router", "query-string", "decode-uri-component", "@react-navigation/core"];
const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8")).packages;

const findings = new Map();
const webFindings = new Map();
for (const vulnerability of Object.values(report.vulnerabilities)) {
  for (const advisory of vulnerability.via) {
    if (typeof advisory !== "object") continue;
    for (const version of shipped.get(advisory.name) ?? []) {
      if (!semver.satisfies(version, advisory.range, { includePrerelease: true })) continue;
      findings.set(`${advisory.name}@${version} ${advisory.url}`, { ...advisory, version });
    }
    const locked = WEB_BUNDLE.includes(advisory.name) && lock[`node_modules/${advisory.name}`]?.version;
    if (locked && semver.satisfies(locked, advisory.range, { includePrerelease: true })) {
      webFindings.set(`${advisory.name} ${advisory.url}`, { ...advisory, version: locked });
    }
  }
}

const RANK = { critical: 4, high: 3, moderate: 2, low: 1 };
const bySeverity = (a, b) =>
  (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0) || (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0) || a.name.localeCompare(b.name);
const rows = [...findings.values()].sort(bySeverity);
const webRows = [...webFindings.values()].sort(bySeverity);
const blocking = rows.filter((row) => BLOCKING.has(row.severity) && !accepted(row));

function table(list, statusOf) {
  if (list.length === 0) return ["None."];
  return [
    "| Package | Severity | CVSS | Advisory | Status |",
    "| --- | --- | --- | --- | --- |",
    ...list.map(
      (row) =>
        `| ${row.name}@${row.version} | ${row.severity} | ${row.cvss?.score || "n/a"} | [${row.title}](${row.url}) | ${statusOf(row)} |`,
    ),
  ];
}

const counts = Object.keys(RANK)
  .map((severity) => `${rows.filter((row) => row.severity === severity).length} ${severity}`)
  .join(", ");
const lines = [
  "## Known advisories in this build",
  "",
  `Electron ${electronVersion}. ${shipped.size} packed packages checked: ${counts}.`,
  "",
  "### Packed into the app",
  "",
  ...table(rows, (row) => {
    if (accepted(row)) return `accepted: ${accepted(row)}`;
    return BLOCKING.has(row.severity) ? "**blocks the build**" : "reported";
  }),
  "",
  "### Web UI bundle (lockfile versions, not verifiable from the app)",
  "",
  ...table(webRows, () => "reported"),
];
const summary = lines.join("\n");
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
// The report ships next to the DMG so whoever installs the build sees what it still carries.
if (process.argv[3]) fs.writeFileSync(process.argv[3], `${summary}\n`);

if (blocking.length > 0) {
  console.error(`\n${blocking.length} high or critical advisories ship in the app. Bump the package or add the advisory to ACCEPTED with a reason.`);
  process.exit(1);
}
