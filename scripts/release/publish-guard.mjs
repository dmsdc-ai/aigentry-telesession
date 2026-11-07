#!/usr/bin/env node
// Release identity / artifact / registry guard for .github/workflows/publish.yml (see docs/ci.md "publish.yml").
// Node built-ins only. Not part of the npm payload (package.json "files" is an allowlist).
// Pure decision functions are exported for test/release-publish-guard.test.js; the CLI at the bottom only
// gathers inputs (git, files, registry) and applies them. Every refusal exits non-zero.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const EXPECTED_REPOSITORY = "dmsdc-ai/aigentry-telesession";
export const EXPECTED_NAME = "@dmsdc-ai/telesession";
export const EXPECTED_REPOSITORY_URL = "git+https://github.com/dmsdc-ai/aigentry-telesession.git";
export const REGISTRY = "https://registry.npmjs.org";
const SHA40 = /^[0-9a-f]{40}$/;
// Stable releases only: a prerelease tag would be published under dist-tag "latest".
const TAG_RE = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

// Commit a remote tag resolves to, from `git ls-remote <url> refs/tags/T refs/tags/T^{}` output.
// Annotated tags: the peeled `^{}` line wins. Absent tag: null.
export function parseLsRemote(text, tag) {
  const direct = `refs/tags/${tag}`, peeled = `${direct}^{}`;
  let directSha = null, peeledSha = null;
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^([0-9a-f]{40})\t(\S+)$/.exec(line.trim());
    if (!m) continue;
    if (m[2] === peeled) peeledSha = m[1];
    else if (m[2] === direct) directSha = m[1];
  }
  return peeledSha || directSha;
}

// HEAD = remote tag commit = GITHUB_SHA; tag = v<package version> = lock versions; exact repository/name.
export function checkIdentity({ eventName, ref, sha, repository, head, remoteTagCommit, pkg, lock }) {
  const errors = [];
  if (eventName !== "push") errors.push(`event '${eventName}' is not a tag push`);
  if (repository !== EXPECTED_REPOSITORY) errors.push(`repository '${repository}' is not ${EXPECTED_REPOSITORY}`);
  const tag = typeof ref === "string" && ref.startsWith("refs/tags/") ? ref.slice("refs/tags/".length) : null;
  if (!tag) errors.push(`ref '${ref}' is not a tag ref`);
  else if (!TAG_RE.test(tag)) errors.push(`tag '${tag}' is not a stable vX.Y.Z tag`);
  if (!SHA40.test(String(sha))) errors.push(`GITHUB_SHA '${sha}' is not a 40-hex commit`);
  if (head !== sha) errors.push(`checkout HEAD ${head} != GITHUB_SHA ${sha}`);
  if (!remoteTagCommit) errors.push(`tag '${tag}' not found on the remote (deleted or never pushed)`);
  else if (remoteTagCommit !== sha) errors.push(`remote tag '${tag}' -> ${remoteTagCommit} != GITHUB_SHA ${sha} (tag moved; refusing)`);
  const version = pkg && pkg.version;
  if (!pkg || pkg.name !== EXPECTED_NAME) errors.push(`package.json name '${pkg && pkg.name}' is not ${EXPECTED_NAME}`);
  if (tag && `v${version}` !== tag) errors.push(`tag '${tag}' != v<package.json version> 'v${version}'`);
  const repoUrl = pkg && pkg.repository && (typeof pkg.repository === "string" ? pkg.repository : pkg.repository.url);
  if (repoUrl !== EXPECTED_REPOSITORY_URL) errors.push(`package.json repository.url '${repoUrl}' is not ${EXPECTED_REPOSITORY_URL}`);
  const root = lock && lock.packages && lock.packages[""];
  if (!lock || lock.name !== EXPECTED_NAME || lock.version !== version) errors.push(`package-lock.json version '${lock && lock.version}' != package.json '${version}'`);
  if (!root || root.name !== EXPECTED_NAME || root.version !== version) errors.push(`package-lock.json packages[""] version '${root && root.version}' != package.json '${version}'`);
  return { ok: errors.length === 0, tag, version, errors };
}

export function digestOf(buf) {
  return {
    integrity: "sha512-" + crypto.createHash("sha512").update(buf).digest("base64"),
    shasum: crypto.createHash("sha1").update(buf).digest("hex"),
    sha256: crypto.createHash("sha256").update(buf).digest("hex"),
    size: buf.length,
  };
}

// Reads one regular file out of a .tgz (ustar, as written by npm pack). Returns null when absent.
export function readTgzEntry(tgz, wanted) {
  const tar = zlib.gunzipSync(tgz);
  for (let off = 0; off + 512 <= tar.length;) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const field = (a, b) => h.subarray(a, b).toString("utf8").replace(/\0[\s\S]*$/, "");
    const name = (field(345, 500) ? field(345, 500) + "/" : "") + field(0, 100);
    const size = parseInt(field(124, 136).trim() || "0", 8);
    const type = field(156, 157) || "0";
    const start = off + 512;
    if (name === wanted && type === "0") return tar.subarray(start, start + size);
    off = start + Math.ceil(size / 512) * 512;
  }
  return null;
}

// Pack result must be self-consistent and carry exactly the expected name/version.
export function checkPack({ packEntry, digest, packedPkg, version }) {
  const errors = [];
  if (!packEntry) errors.push("npm pack --json produced no entry");
  else {
    if (packEntry.name !== EXPECTED_NAME || packEntry.version !== version) errors.push(`npm pack reported ${packEntry.name}@${packEntry.version}, expected ${EXPECTED_NAME}@${version}`);
    if (packEntry.integrity !== digest.integrity) errors.push(`npm pack integrity ${packEntry.integrity} != measured ${digest.integrity}`);
    if (packEntry.shasum !== digest.shasum) errors.push(`npm pack shasum ${packEntry.shasum} != measured ${digest.shasum}`);
  }
  if (!packedPkg || packedPkg.name !== EXPECTED_NAME || packedPkg.version !== version) errors.push(`packed package/package.json is ${packedPkg && packedPkg.name}@${packedPkg && packedPkg.version}, expected ${EXPECTED_NAME}@${version}`);
  return { ok: errors.length === 0, errors };
}

// The tested tarball: the Ubuntu leg of this run's compatibility.yml (Node 20.20.0, exact Telepty pin) packed it,
// installed it and ran test:installed against it. Its artifact (common root $RUNNER_TEMP/compat) carries
// provenance.json, tarball.json, pack.json, installed.log, full.tap and pack/<filename>. Accepted only when every
// binding below holds; a prior attempt of the SAME run (run.attempt <= current) is valid reuse.
export const COMPAT_MATRIX = { os: "ubuntu-latest", runner_os: "Linux", node: "v20.20.0" };
export const TELEPTY_REPOSITORY = "dmsdc-ai/aigentry-telepty";
export const expectedFilename = (version) => `${EXPECTED_NAME.slice(1).replace("/", "-")}-${version}.tgz`;

export function checkCompatArtifact({ provenance, tarballMeta, packJson, tgzNames, digest, packedPkg, installedLog, fullTap,
  sha, ref, runId, runAttempt, version, teleptySha }) {
  const errors = [], p = provenance || {}, ts = p.telesession || {}, tp = p.telepty || {}, mx = p.matrix || {}, run = p.run || {};
  const filename = expectedFilename(version);
  if (!provenance) errors.push("provenance.json missing or unreadable");
  if (ts.sha !== sha) errors.push(`provenance telesession.sha ${ts.sha} != GITHUB_SHA ${sha}`);
  if (ts.dispatched_sha !== sha) errors.push(`provenance telesession.dispatched_sha ${ts.dispatched_sha} != GITHUB_SHA ${sha}`);
  if (ts.ref !== ref) errors.push(`provenance telesession.ref ${ts.ref} != GITHUB_REF ${ref}`);
  if (ts.version !== version) errors.push(`provenance telesession.version ${ts.version} != ${version}`);
  if (tp.repository !== TELEPTY_REPOSITORY) errors.push(`provenance telepty.repository ${tp.repository} != ${TELEPTY_REPOSITORY}`);
  if (!SHA40.test(String(teleptySha)) || tp.sha !== teleptySha) errors.push(`provenance telepty.sha ${tp.sha} != pinned ${teleptySha}`);
  for (const k of Object.keys(COMPAT_MATRIX)) if (mx[k] !== COMPAT_MATRIX[k]) errors.push(`provenance matrix.${k} ${mx[k]} != ${COMPAT_MATRIX[k]}`);
  if (String(run.id) !== String(runId) || !/^[0-9]+$/.test(String(runId))) errors.push(`provenance run.id ${run.id} != GITHUB_RUN_ID ${runId} (another run is never accepted)`);
  const a = Number(run.attempt), cur = Number(runAttempt);
  if (!/^[0-9]+$/.test(String(run.attempt)) || !Number.isInteger(cur) || a < 1 || a > cur) errors.push(`provenance run.attempt ${run.attempt} not in 1..${runAttempt}`);
  if (!Array.isArray(tgzNames) || tgzNames.length !== 1 || tgzNames[0] !== filename) errors.push(`pack/ holds ${JSON.stringify(tgzNames)}, expected exactly ["${filename}"]`);
  if (!tarballMeta || tarballMeta.filename !== filename) errors.push(`tarball.json filename ${tarballMeta && tarballMeta.filename} != ${filename}`);
  if (!digest) errors.push("tarball bytes missing");
  else {
    if (!tarballMeta || tarballMeta.sha256 !== digest.sha256) errors.push(`tarball.json sha256 ${tarballMeta && tarballMeta.sha256} != measured ${digest.sha256}`);
    if (!tarballMeta || tarballMeta.integrity !== digest.integrity) errors.push(`tarball.json integrity ${tarballMeta && tarballMeta.integrity} != measured ${digest.integrity}`);
  }
  const entry = Array.isArray(packJson) && packJson.length === 1 ? packJson[0] : null;
  if (!entry) errors.push("pack.json is not a single npm pack entry");
  else if (path.basename(String(entry.filename)) !== filename) errors.push(`pack.json filename ${entry.filename} != ${filename}`);
  if (digest) errors.push(...checkPack({ packEntry: entry, digest, packedPkg, version }).errors);
  if (!installedLog) errors.push("installed.log missing or empty (installed-artifact acceptance not evidenced)");
  if (!fullTap) errors.push("full.tap missing or empty");
  return { ok: errors.length === 0, filename, errors };
}

export function checkDigest(record, digest) {
  const errors = [];
  for (const k of ["integrity", "shasum", "sha256", "size"]) if (record[k] !== digest[k]) errors.push(`${k}: recorded ${record[k]} != measured ${digest[k]}`);
  return { ok: errors.length === 0, errors };
}

// Registry state for <name>@<version> from one packument GET.
//   absent            : 200, exact package, version not listed (definite absence -> may publish)
//   published-match   : version listed with exactly the measured integrity and shasum (reconcile, never re-publish)
//   published-mismatch: version listed with any other artifact (fail; never overwrite)
//   unknown           : anything else - network error, non-200 (404 included: the package already exists),
//                       malformed body, other package name (fail; evidence preserved)
export function classifyRegistry({ status, body, error, name, version, integrity, shasum }) {
  if (error) return { state: "unknown", detail: `request failed: ${error}` };
  if (status !== 200) return { state: "unknown", detail: `HTTP ${status}` };
  let doc;
  try { doc = typeof body === "string" ? JSON.parse(body) : body; } catch (e) { return { state: "unknown", detail: `malformed JSON: ${e.message}` }; }
  if (!doc || typeof doc !== "object" || doc.name !== name) return { state: "unknown", detail: `packument name '${doc && doc.name}' != ${name}` };
  if (!doc.versions || typeof doc.versions !== "object") return { state: "unknown", detail: "packument has no versions object" };
  const v = Object.prototype.hasOwnProperty.call(doc.versions, version) ? doc.versions[version] : undefined;
  if (v === undefined) return { state: "absent", detail: `${name}@${version} not listed`, latest: doc["dist-tags"] && doc["dist-tags"].latest };
  const dist = (v && v.dist) || {};
  const evidence = { integrity: dist.integrity, shasum: dist.shasum, tarball: dist.tarball, attestations: dist.attestations || null, gitHead: v.gitHead || null, latest: doc["dist-tags"] && doc["dist-tags"].latest };
  if (v.version === version && dist.integrity === integrity && dist.shasum === shasum) return { state: "published-match", detail: "registry serves the measured artifact", ...evidence };
  return { state: "published-mismatch", detail: `registry ${version} integrity ${dist.integrity} != measured ${integrity}`, ...evidence };
}

// What the publish job may do for a given state. Only definite absence publishes.
export function publishDecision(state) {
  if (state === "absent") return "publish";
  if (state === "published-match") return "reconcile";
  return "refuse";
}

// ---------------------------------------------------------------- CLI (workflow use only)

function readJson(file) { return JSON.parse(fs.readFileSync(file, "utf8")); }
function setOutput(key, value) { if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`); }
function writeEvidence(file, obj) { fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); console.log(JSON.stringify(obj)); }
function fail(errors) { for (const e of errors) console.error(`::error::${e}`); process.exit(1); }
function git(args) { return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }

async function fetchPackument(name) {
  const url = `${REGISTRY}/@${encodeURIComponent(name.slice(1))}`;
  try {
    const res = await fetch(url, { headers: { accept: "application/json", "cache-control": "no-cache" } });
    return { url, status: res.status, body: await res.text() };
  } catch (e) { return { url, error: String(e && e.message || e) }; }
}

async function registryState(record) {
  const r = await fetchPackument(record.name);
  return { url: r.url, status: r.status ?? null, at: new Date().toISOString(),
    ...classifyRegistry({ ...r, name: record.name, version: record.version, integrity: record.integrity, shasum: record.shasum }) };
}

const commands = {
  // identity <outfile>
  identity(out) {
    const env = process.env, tag = (env.GITHUB_REF || "").replace(/^refs\/tags\//, "");
    const head = git(["rev-parse", "HEAD"]).trim();
    let remote = "";
    if (TAG_RE.test(tag) && env.GITHUB_REPOSITORY === EXPECTED_REPOSITORY) {
      remote = git(["ls-remote", "--tags", `https://github.com/${EXPECTED_REPOSITORY}.git`, `refs/tags/${tag}`, `refs/tags/${tag}^{}`]);
    }
    const r = checkIdentity({ eventName: env.GITHUB_EVENT_NAME, ref: env.GITHUB_REF, sha: env.GITHUB_SHA, repository: env.GITHUB_REPOSITORY,
      head, remoteTagCommit: parseLsRemote(remote, tag), pkg: readJson("package.json"), lock: readJson("package-lock.json") });
    writeEvidence(out, { ...r, head, github_sha: env.GITHUB_SHA, ref: env.GITHUB_REF, ls_remote: remote, run_id: env.GITHUB_RUN_ID, run_attempt: env.GITHUB_RUN_ATTEMPT });
    if (!r.ok) fail(r.errors);
    setOutput("tag", r.tag); setOutput("version", r.version);
  },
  // select-compat <compat-artifact-dir> <version> <telepty-sha> <artifact-name> <outdir>
  // Accepts the tested Ubuntu compatibility tarball (see checkCompatArtifact) and emits the release-tarball
  // interface from exactly those bytes: <outdir>/pkg/<filename>, <outdir>/record.json, <outdir>/source/*.json.
  "select-compat"(dir, version, teleptySha, artifactName, out) {
    const env = process.env;
    const tryJson = (file) => { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return null; } };
    const nonEmpty = (file) => { try { return fs.statSync(file).isFile() && fs.statSync(file).size > 0; } catch { return false; } };
    let tgzNames = [];
    try { tgzNames = fs.readdirSync(path.join(dir, "pack")).filter((n) => n.endsWith(".tgz")).sort(); } catch { tgzNames = []; }
    let buf = null, packedPkg = null;
    if (tgzNames.length === 1) {
      try { buf = fs.readFileSync(path.join(dir, "pack", tgzNames[0])); } catch { buf = null; }
      try { const e = buf && readTgzEntry(buf, "package/package.json"); packedPkg = e && JSON.parse(e.toString("utf8")); } catch { packedPkg = null; }
    }
    const digest = buf && digestOf(buf);
    const provenance = tryJson(path.join(dir, "provenance.json")), tarballMeta = tryJson(path.join(dir, "tarball.json")), packJson = tryJson(path.join(dir, "pack.json"));
    const r = checkCompatArtifact({ provenance, tarballMeta, packJson, tgzNames, digest, packedPkg,
      installedLog: nonEmpty(path.join(dir, "installed.log")), fullTap: nonEmpty(path.join(dir, "full.tap")),
      sha: env.GITHUB_SHA, ref: env.GITHUB_REF, runId: env.GITHUB_RUN_ID, runAttempt: env.GITHUB_RUN_ATTEMPT, version, teleptySha });
    fs.mkdirSync(path.join(out, "source"), { recursive: true });
    for (const [n, v] of [["provenance.json", provenance], ["tarball.json", tarballMeta], ["pack.json", packJson]]) if (v) fs.writeFileSync(path.join(out, "source", n), JSON.stringify(v, null, 2) + "\n");
    const entry = Array.isArray(packJson) ? packJson[0] || {} : {};
    const record = { name: EXPECTED_NAME, version, filename: r.filename, ...(digest || {}), entryCount: entry.entryCount, commit: env.GITHUB_SHA,
      source: { artifact: artifactName, workflow: "compatibility.yml", provenance } };
    writeEvidence(path.join(out, "record.json"), record);
    if (!r.ok) fail(r.errors);
    fs.mkdirSync(path.join(out, "pkg"), { recursive: true });
    fs.writeFileSync(path.join(out, "pkg", r.filename), buf);
    for (const k of ["filename", "integrity", "shasum", "sha256"]) setOutput(k, record[k]);
  },
  // verify-tgz <record.json> <tgz>
  "verify-tgz"(recordFile, tgz) {
    const r = checkDigest(readJson(recordFile), digestOf(fs.readFileSync(tgz)));
    if (!r.ok) fail(r.errors);
    console.log("tarball matches the measured record");
  },
  // registry-state <record.json> <outfile>
  async "registry-state"(recordFile, out) {
    const s = await registryState(readJson(recordFile));
    writeEvidence(out, s);
    setOutput("state", s.state); setOutput("decision", publishDecision(s.state));
    if (publishDecision(s.state) === "refuse") fail([`registry state ${s.state}: ${s.detail}`]);
  },
  // readback <record.json> <outfile> [attempts] [intervalSeconds]
  async readback(recordFile, out, attempts = "20", interval = "15") {
    const record = readJson(recordFile), log = [];
    for (let i = 1; i <= Number(attempts); i++) {
      const s = await registryState(record);
      log.push(s);
      if (s.state === "published-match" || s.state === "published-mismatch") {
        writeEvidence(out, { final: s, attempts: log });
        if (s.state !== "published-match") fail([`readback: ${s.detail}`]);
        return;
      }
      if (i < Number(attempts)) await new Promise((r) => setTimeout(r, Number(interval) * 1000));
    }
    writeEvidence(out, { final: log[log.length - 1], attempts: log });
    fail([`readback: ${record.name}@${record.version} with the measured integrity not served after ${attempts} attempts`]);
  },
};

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [cmd, ...args] = process.argv.slice(2);
  if (!Object.prototype.hasOwnProperty.call(commands, cmd)) fail([`unknown command '${cmd}'`]);
  await commands[cmd](...args);
}
