// Fails when a package packed into the desktop app matches a high or critical npm advisory.
// `npm audit` alone cannot gate this build: it also counts the website, Expo tooling and test
// runners, none of which reach the DMG.
// Not covered: packages Metro bundles into Resources/app-dist, which keep no package metadata.
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const semver = require("semver");

// Advisories that only a semver-major upgrade fixes. Remove an entry once upstream upgrades.
const ACCEPTED = {
  "markdown-it": "fix needs markdown-it 15 (major); quadratic-time parsing of hostile Markdown",
  "linkify-it": "pulled in by markdown-it 10; same upgrade",
};
const BLOCKING = new Set(["high", "critical"]);

const appPath = process.argv[2];
if (!appPath) throw new Error("usage: audit-shipped.cjs <path to Paseo.app>");
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

// npm audit exits non-zero whenever it finds anything, so only the JSON matters.
const audit = spawnSync("npm", ["audit", "--json"], { encoding: "utf8", maxBuffer: 1 << 28 });
const report = JSON.parse(audit.stdout);
if (!report.vulnerabilities) throw new Error(`npm audit returned no report: ${audit.stdout.slice(0, 400)}`);

const findings = new Map();
for (const vulnerability of Object.values(report.vulnerabilities)) {
  for (const advisory of vulnerability.via) {
    if (typeof advisory !== "object") continue;
    for (const version of shipped.get(advisory.name) ?? []) {
      if (!semver.satisfies(version, advisory.range, { includePrerelease: true })) continue;
      findings.set(`${advisory.name}@${version} ${advisory.url}`, { ...advisory, version });
    }
  }
}

const rows = [...findings.values()].sort((a, b) => a.name.localeCompare(b.name));
const blocking = rows.filter((row) => BLOCKING.has(row.severity) && !ACCEPTED[row.name]);
const lines = [
  `### Advisories in the packaged app (${shipped.size} packages checked)`,
  "",
  "| Package | Severity | Advisory | Status |",
  "| --- | --- | --- | --- |",
  ...rows.map((row) => {
    let status = "reported";
    if (ACCEPTED[row.name]) status = `accepted: ${ACCEPTED[row.name]}`;
    else if (BLOCKING.has(row.severity)) status = "**blocks the build**";
    return `| ${row.name}@${row.version} | ${row.severity} | [${row.title}](${row.url}) | ${status} |`;
  }),
  rows.length === 0 ? "| none | | | |" : "",
];
const summary = lines.join("\n");
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);

if (blocking.length > 0) {
  console.error(`\n${blocking.length} high or critical advisories ship in the app. Bump the package or add it to ACCEPTED with a reason.`);
  process.exit(1);
}
