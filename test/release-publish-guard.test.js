// Release contract for .github/workflows/publish.yml and scripts/release/publish-guard.mjs (docs/ci.md "publish.yml").
// Pure decision functions only: no network, no git, no npm. The workflow is asserted as text (no YAML dependency).

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import {
  parseLsRemote, checkIdentity, digestOf, readTgzEntry, checkPack, checkDigest, classifyRegistry, publishDecision,
  checkCompatArtifact, expectedFilename, EXPECTED_NAME, EXPECTED_REPOSITORY, EXPECTED_REPOSITORY_URL,
} from "../scripts/release/publish-guard.mjs";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "a".repeat(40), OTHER = "b".repeat(40), TAGOBJ = "c".repeat(40);
const pkg = (version = "0.2.1", extra = {}) => ({ name: EXPECTED_NAME, version, repository: { type: "git", url: EXPECTED_REPOSITORY_URL }, ...extra });
const lock = (version = "0.2.1", rootVersion = version) => ({ name: EXPECTED_NAME, version, packages: { "": { name: EXPECTED_NAME, version: rootVersion } } });
const base = (over = {}) => ({ eventName: "push", ref: "refs/tags/v0.2.1", sha: SHA, repository: EXPECTED_REPOSITORY, head: SHA,
  remoteTagCommit: SHA, pkg: pkg(), lock: lock(), ...over });

test("identity: tag commit = HEAD = GITHUB_SHA and v<version> = lock versions passes", () => {
  const r = checkIdentity(base());
  assert.deepEqual(r, { ok: true, tag: "v0.2.1", version: "0.2.1", errors: [] });
});

test("identity: HEAD != GITHUB_SHA is refused", () => {
  const r = checkIdentity(base({ head: OTHER }));
  assert.equal(r.ok, false);
  assert.match(r.errors.join("\n"), /checkout HEAD .* != GITHUB_SHA/);
});

test("identity: remote tag moved to another commit (re-run after tag move) is refused", () => {
  const r = checkIdentity(base({ remoteTagCommit: OTHER }));
  assert.equal(r.ok, false);
  assert.match(r.errors.join("\n"), /remote tag 'v0\.2\.1' -> b{40} != GITHUB_SHA/);
});

test("identity: remote tag deleted is refused", () => {
  const r = checkIdentity(base({ remoteTagCommit: null }));
  assert.equal(r.ok, false);
  assert.match(r.errors.join("\n"), /not found on the remote/);
});

test("identity: non-tag ref, non-push event, prerelease tag and foreign repository are refused", () => {
  assert.match(checkIdentity(base({ ref: "refs/heads/main" })).errors.join("\n"), /not a tag ref/);
  assert.match(checkIdentity(base({ eventName: "workflow_dispatch" })).errors.join("\n"), /not a tag push/);
  assert.match(checkIdentity(base({ ref: "refs/tags/v0.2.1-rc.1", pkg: pkg("0.2.1-rc.1"), lock: lock("0.2.1-rc.1") })).errors.join("\n"), /not a stable vX\.Y\.Z tag/);
  assert.match(checkIdentity(base({ repository: "someone/fork" })).errors.join("\n"), /repository 'someone\/fork'/);
  assert.match(checkIdentity(base({ sha: "abc", head: "abc", remoteTagCommit: "abc" })).errors.join("\n"), /not a 40-hex commit/);
});

test("identity: tag != package.json version, or lock root/packages[\"\"] drift, is refused", () => {
  assert.match(checkIdentity(base({ ref: "refs/tags/v0.2.0" })).errors.join("\n"), /tag 'v0\.2\.0' != v<package\.json version> 'v0\.2\.1'/);
  assert.match(checkIdentity(base({ lock: lock("0.2.0", "0.2.1") })).errors.join("\n"), /package-lock\.json version '0\.2\.0'/);
  assert.match(checkIdentity(base({ lock: lock("0.2.1", "0.2.0") })).errors.join("\n"), /packages\[""\] version '0\.2\.0'/);
});

test("identity: package name and repository.url must be exact (provenance source)", () => {
  assert.match(checkIdentity(base({ pkg: pkg("0.2.1", { name: "telesession" }) })).errors.join("\n"), /name 'telesession'/);
  assert.match(checkIdentity(base({ pkg: pkg("0.2.1", { repository: undefined }) })).errors.join("\n"), /repository\.url 'undefined'/);
});

test("ls-remote: annotated tag uses the peeled commit; lightweight uses the direct line; absent is null", () => {
  const annotated = `${TAGOBJ}\trefs/tags/v0.2.1\n${SHA}\trefs/tags/v0.2.1^{}\n`;
  assert.equal(parseLsRemote(annotated, "v0.2.1"), SHA);
  assert.equal(parseLsRemote(`${SHA}\trefs/tags/v0.2.1\n`, "v0.2.1"), SHA);
  assert.equal(parseLsRemote(`${SHA}\trefs/tags/v0.2.10\n`, "v0.2.1"), null);
  assert.equal(parseLsRemote("", "v0.2.1"), null);
});

// Minimal ustar writer for fixtures.
function tgzOf(files) {
  const blocks = [];
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content), h = Buffer.alloc(512);
    h.write(name, 0, 100); h.write("0000644\0", 100); h.write("0000000\0", 108); h.write("0000000\0", 116);
    h.write(data.length.toString(8).padStart(11, "0") + "\0", 124); h.write("00000000000\0", 136);
    h.write("        ", 148); h.write("0", 156); h.write("ustar\0", 257); h.write("00", 263);
    let sum = 0; for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(blocks));
}

test("pack: measured digests, npm pack report and packed package.json must agree", () => {
  const tgz = tgzOf({ "package/README.md": "x", "package/package.json": JSON.stringify({ name: EXPECTED_NAME, version: "0.2.1" }) });
  const digest = digestOf(tgz);
  assert.match(digest.integrity, /^sha512-/);
  assert.equal(JSON.parse(readTgzEntry(tgz, "package/package.json").toString()).version, "0.2.1");
  assert.equal(readTgzEntry(tgz, "package/missing.json"), null);
  const entry = { name: EXPECTED_NAME, version: "0.2.1", integrity: digest.integrity, shasum: digest.shasum };
  const packedPkg = { name: EXPECTED_NAME, version: "0.2.1" };
  assert.equal(checkPack({ packEntry: entry, digest, packedPkg, version: "0.2.1" }).ok, true);
  assert.equal(checkPack({ packEntry: { ...entry, integrity: "sha512-other" }, digest, packedPkg, version: "0.2.1" }).ok, false);
  assert.equal(checkPack({ packEntry: entry, digest, packedPkg: { ...packedPkg, version: "0.2.0" }, version: "0.2.1" }).ok, false);
  assert.equal(checkPack({ packEntry: { ...entry, version: "0.2.0" }, digest, packedPkg, version: "0.2.1" }).ok, false);
});

test("artifact: a tarball differing from the measured record is refused (no repack substitution)", () => {
  const a = digestOf(Buffer.from("measured")), b = digestOf(Buffer.from("different"));
  assert.equal(checkDigest({ ...a }, a).ok, true);
  const r = checkDigest({ ...a }, b);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.startsWith("integrity:")));
});

const M = { name: EXPECTED_NAME, version: "0.2.1", integrity: "sha512-measured", shasum: "1".repeat(40) };
const doc = (versions) => JSON.stringify({ name: EXPECTED_NAME, "dist-tags": { latest: "0.2.0" }, versions });

test("registry: definite absence (200, exact package, version not listed) is the only publish path", () => {
  const s = classifyRegistry({ status: 200, body: doc({ "0.2.0": { version: "0.2.0", dist: {} } }), ...M });
  assert.equal(s.state, "absent");
  assert.equal(publishDecision(s.state), "publish");
});

test("registry: already published with the exact measured artifact reconciles without a second publish", () => {
  const s = classifyRegistry({ status: 200, body: doc({ "0.2.1": { version: "0.2.1", gitHead: SHA, dist: { integrity: M.integrity, shasum: M.shasum, attestations: { url: "u" } } } }), ...M });
  assert.equal(s.state, "published-match");
  assert.equal(publishDecision(s.state), "reconcile");
  assert.deepEqual(s.attestations, { url: "u" });
});

test("registry: version exists with a different artifact is refused (no blind success on existence)", () => {
  const s1 = classifyRegistry({ status: 200, body: doc({ "0.2.1": { version: "0.2.1", dist: { integrity: "sha512-other", shasum: M.shasum } } }), ...M });
  const s2 = classifyRegistry({ status: 200, body: doc({ "0.2.1": { version: "0.2.1", dist: { integrity: M.integrity, shasum: "2".repeat(40) } } }), ...M });
  const s3 = classifyRegistry({ status: 200, body: doc({ "0.2.1": { version: "0.2.1" } }), ...M });
  for (const s of [s1, s2, s3]) { assert.equal(s.state, "published-mismatch"); assert.equal(publishDecision(s.state), "refuse"); }
});

test("registry: errors other than definite absence are unknown and refused", () => {
  const cases = [
    { error: "ECONNRESET" },
    { status: 404, body: "{\"error\":\"Not found\"}" },
    { status: 500, body: "" },
    { status: 429, body: "" },
    { status: 200, body: "<html>" },
    { status: 200, body: JSON.stringify({ name: "other", versions: {} }) },
    { status: 200, body: JSON.stringify({ name: EXPECTED_NAME }) },
  ];
  for (const c of cases) {
    const s = classifyRegistry({ ...c, ...M });
    assert.equal(s.state, "unknown", JSON.stringify(c));
    assert.equal(publishDecision(s.state), "refuse");
  }
});

// Tested-artifact binding (M1): the Ubuntu compatibility leg's own tarball and metadata, as compatibility.yml writes them.
const PIN = "556a4ba3bcbdbcd42d2cca1bdf14a0f3cef7e421";
const TESTED = tgzOf({ "package/package.json": JSON.stringify({ name: EXPECTED_NAME, version: "0.2.1" }), "package/README.md": "r" });
const TD = digestOf(TESTED);
const compat = (over = {}) => {
  const c = {
    provenance: {
      telesession: { sha: SHA, dispatched_sha: SHA, ref: "refs/tags/v0.2.1", version: "0.2.1" },
      telepty: { repository: "dmsdc-ai/aigentry-telepty", sha: PIN, version: "0.10.0" },
      matrix: { os: "ubuntu-latest", runner_os: "Linux", arch: "X64", node: "v20.20.0", npm: "10.8.2" },
      run: { id: "123456", attempt: "1" },
    },
    tarballMeta: { filename: "dmsdc-ai-telesession-0.2.1.tgz", sha256: TD.sha256, integrity: TD.integrity, entries: 2 },
    packJson: [{ name: EXPECTED_NAME, version: "0.2.1", filename: "dmsdc-ai-telesession-0.2.1.tgz", integrity: TD.integrity, shasum: TD.shasum, entryCount: 2 }],
    tgzNames: ["dmsdc-ai-telesession-0.2.1.tgz"], digest: TD, packedPkg: { name: EXPECTED_NAME, version: "0.2.1" },
    installedLog: true, fullTap: true,
    sha: SHA, ref: "refs/tags/v0.2.1", runId: "123456", runAttempt: "1", version: "0.2.1", teleptySha: PIN,
  };
  return over(c) || c;
};
const errs = (c) => checkCompatArtifact(c).errors.join("\n");

test("compat artifact: the tested Ubuntu tarball with matching provenance, metadata and bytes is accepted", () => {
  assert.equal(expectedFilename("0.2.1"), "dmsdc-ai-telesession-0.2.1.tgz");
  assert.deepEqual(checkCompatArtifact(compat(() => {})), { ok: true, filename: "dmsdc-ai-telesession-0.2.1.tgz", errors: [] });
});

test("compat artifact: same-run prior-attempt reuse is valid; a later attempt than the current one is not", () => {
  assert.equal(checkCompatArtifact(compat((c) => { c.runAttempt = "3"; c.provenance.run.attempt = "1"; })).ok, true);
  assert.equal(checkCompatArtifact(compat((c) => { c.runAttempt = "2"; c.provenance.run.attempt = "2"; })).ok, true);
  assert.match(errs(compat((c) => { c.runAttempt = "1"; c.provenance.run.attempt = "2"; })), /run\.attempt 2 not in 1\.\.1/);
  assert.match(errs(compat((c) => { c.provenance.run.attempt = "0"; })), /run\.attempt 0/);
});

test("compat artifact: another run or another source commit/ref/version is refused", () => {
  assert.match(errs(compat((c) => { c.provenance.run.id = "999"; })), /run\.id 999 != GITHUB_RUN_ID 123456/);
  assert.match(errs(compat((c) => { c.provenance.telesession.sha = OTHER; })), /telesession\.sha b{40} != GITHUB_SHA/);
  assert.match(errs(compat((c) => { c.provenance.telesession.dispatched_sha = OTHER; })), /dispatched_sha b{40}/);
  assert.match(errs(compat((c) => { c.provenance.telesession.ref = "refs/heads/main"; })), /telesession\.ref refs\/heads\/main/);
  assert.match(errs(compat((c) => { c.provenance.telesession.version = "0.2.0"; })), /telesession\.version 0\.2\.0 != 0\.2\.1/);
  assert.match(errs(compat((c) => { c.provenance = null; })), /provenance\.json missing/);
});

test("compat artifact: wrong Telepty pin or matrix leg is refused", () => {
  assert.match(errs(compat((c) => { c.provenance.telepty.sha = OTHER; })), /telepty\.sha b{40} != pinned 556a4ba/);
  assert.match(errs(compat((c) => { c.provenance.telepty.repository = "someone/telepty"; })), /telepty\.repository someone\/telepty/);
  assert.match(errs(compat((c) => { c.provenance.matrix.os = "macos-latest"; })), /matrix\.os macos-latest != ubuntu-latest/);
  assert.match(errs(compat((c) => { c.provenance.matrix.runner_os = "macOS"; })), /matrix\.runner_os macOS != Linux/);
  assert.match(errs(compat((c) => { c.provenance.matrix.node = "v24.22.2"; })), /matrix\.node v24\.22\.2 != v20\.20\.0/);
});

test("compat artifact: filename, hash or version metadata that disagree with the bytes are refused", () => {
  assert.match(errs(compat((c) => { c.tgzNames = ["dmsdc-ai-telesession-0.2.0.tgz"]; })), /pack\/ holds/);
  assert.match(errs(compat((c) => { c.tgzNames.push("extra.tgz"); })), /expected exactly/);
  assert.match(errs(compat((c) => { c.tgzNames = []; c.digest = null; })), /tarball bytes missing/);
  assert.match(errs(compat((c) => { c.tarballMeta.filename = "other.tgz"; })), /tarball\.json filename other\.tgz/);
  assert.match(errs(compat((c) => { c.packJson[0].filename = "other.tgz"; })), /pack\.json filename other\.tgz/);
  assert.match(errs(compat((c) => { c.tarballMeta.sha256 = "0".repeat(64); })), /tarball\.json sha256/);
  assert.match(errs(compat((c) => { c.tarballMeta.integrity = "sha512-x"; })), /tarball\.json integrity sha512-x/);
  assert.match(errs(compat((c) => { c.packJson[0].shasum = "0".repeat(40); })), /npm pack shasum/);
  assert.match(errs(compat((c) => { c.packJson = []; })), /pack\.json is not a single npm pack entry/);
  const altered = digestOf(Buffer.concat([TESTED, Buffer.from([0])]));
  assert.match(errs(compat((c) => { c.digest = altered; })), /sha256 .* != measured/);
  assert.match(errs(compat((c) => { c.packedPkg = { name: EXPECTED_NAME, version: "0.2.0" }; })), /packed package\/package\.json/);
  assert.match(errs(compat((c) => { c.version = "0.2.2"; })), /expected exactly \["dmsdc-ai-telesession-0\.2\.2\.tgz"\]/);
});

test("compat artifact: missing installed-acceptance or full-suite evidence is refused", () => {
  assert.match(errs(compat((c) => { c.installedLog = false; })), /installed\.log missing/);
  assert.match(errs(compat((c) => { c.fullTap = false; })), /full\.tap missing/);
});

test("publish.yml: tag-only trigger, OIDC on the publish job only, no tokens, no repack, pinned Telepty", () => {
  const y = fs.readFileSync(path.join(ROOT, ".github/workflows/publish.yml"), "utf8");
  const code = y.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join("\n");
  assert.match(code, /^on:\n  push:\n    tags: \["v\*"\]\n\npermissions:\n  contents: read\n/m);
  assert.doesNotMatch(code, /workflow_dispatch|workflow_call|pull_request|inputs\./);
  assert.equal((code.match(/id-token: write/g) || []).length, 1);
  const publishJob = code.slice(code.indexOf("\n  publish:\n"), code.indexOf("\n  verify:\n"));
  assert.match(publishJob, /permissions:\n      contents: read\n      id-token: write/);
  assert.doesNotMatch(code, /NODE_AUTH_TOKEN|NPM_TOKEN|secrets\.|_authToken|whoami|registry-url/);
  assert.match(code, /concurrency:\n  group: publish-\$\{\{ github\.ref \}\}\n  cancel-in-progress: false/);
  // No npm pack in this workflow: the tarball is the Ubuntu compatibility leg's tested artifact of this run.
  assert.doesNotMatch(code, /^\s*(?:\S+=\S+ )*npm pack\b/m);
  const packJob = code.slice(code.indexOf("\n  pack:\n"), code.indexOf("\n  registry-state:\n"));
  assert.match(packJob, /name: tested-compatibility-ubuntu-latest-node-20\.20\.0-telepty-556a4ba3bcbdbcd42d2cca1bdf14a0f3cef7e421\n/);
  assert.match(packJob, /COMPAT_ARTIFACT: tested-compatibility-ubuntu-latest-node-20\.20\.0-telepty-556a4ba3bcbdbcd42d2cca1bdf14a0f3cef7e421\n/);
  assert.doesNotMatch(code, /name: compatibility-/);
  assert.match(packJob, /publish-guard\.mjs select-compat /);
  assert.doesNotMatch(code, /run-id:|github-token:|repository: /);
  assert.equal((code.match(/node-version: "24\.22\.2"/g) || []).length, 4);
  assert.doesNotMatch(code, /24\.11\.0/);
  assert.equal((code.match(/^\s*(?:npm_config_userconfig="[^"]*" \\\n\s*)?npm publish /gm) || []).length, 1);
  assert.match(code, /npm publish "\$RUNNER_TEMP\/release\/pkg\/\$FILENAME" --access public/);
  assert.match(code, /TELEPTY_SHA: 556a4ba3bcbdbcd42d2cca1bdf14a0f3cef7e421/);
  assert.match(code, /uses: \.\/\.github\/workflows\/ci\.yml/);
  assert.match(code, /uses: \.\/\.github\/workflows\/compatibility\.yml/);
  assert.match(publishJob, /if: \$\{\{ needs\.registry-state\.outputs\.decision == 'publish' \}\}/);
  // Untrusted refs never interpolated into shell: no ${{ github.ref* }} / head_ref inside run blocks.
  assert.doesNotMatch(code, /run: [^\n]*\$\{\{|^\s+[^\n]*\$\{\{ github\.(ref_name|head_ref|event)/m);
});

test("compatibility.yml: tested artifact only after all Ubuntu gates passed; diagnostics always and attempt-qualified (R4)", () => {
  const y = fs.readFileSync(path.join(ROOT, ".github/workflows/compatibility.yml"), "utf8");
  const code = y.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join("\n");
  const steps = code.split(/\n(?=      - )/);
  const tested = steps.filter((st) => /name: tested-compatibility-/.test(st));
  const raw = steps.filter((st) => /name: compatibility-/.test(st) && /upload-artifact/.test(st));
  assert.equal(tested.length, 1, "exactly one tested-artifact upload");
  assert.equal(raw.length, 1, "exactly one diagnostic upload");
  const t = tested[0], r = raw[0];
  assert.match(t, /\n        if: \$\{\{ success\(\) && runner\.os == 'Linux' && matrix\.os == 'ubuntu-latest' && steps\.full\.outcome == 'success' && steps\.packtest\.outcome == 'success' && steps\.installed\.outcome == 'success' \}\}\n/);
  assert.match(t, /uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n/);
  assert.match(t, /name: tested-compatibility-\$\{\{ matrix\.os \}\}-node-\$\{\{ matrix\.node \}\}-telepty-\$\{\{ inputs\.telepty_ref \}\}\n/);
  assert.match(t, /\n          overwrite: true\n/);
  assert.match(t, /\n          if-no-files-found: error\n/);
  assert.match(t, /\n          retention-days: 14\n?/);
  const paths = [...t.matchAll(/^            \$\{\{ runner\.temp \}\}\/compat\/(\S+)$/gm)].map((m) => m[1]).sort();
  assert.deepEqual(paths, ["full.tap", "installed.log", "pack.json", "pack/", "provenance.json", "tarball.json"]);
  assert.doesNotMatch(t, /prefix|npm-cache|npmrc|node_modules|child-logs/);
  // The tested upload is the last step, after the counts and the diagnostic upload.
  assert.equal(steps[steps.length - 1], t);
  assert.ok(steps.indexOf(r) < steps.indexOf(t) && steps.findIndex((st) => /name: Counts/.test(st)) < steps.indexOf(r));
  assert.match(r, /\n        if: always\(\)\n/);
  assert.match(r, /name: compatibility-\$\{\{ matrix\.os \}\}-node-\$\{\{ matrix\.node \}\}-telepty-\$\{\{ inputs\.telepty_ref \}\}-attempt-\$\{\{ github\.run_attempt \}\}\n/);
  assert.doesNotMatch(r, /overwrite:/);
  // publish.yml consumes exactly the tested name for the pinned matrix leg, never the diagnostic one.
  const p = fs.readFileSync(path.join(ROOT, ".github/workflows/publish.yml"), "utf8");
  const pin = /TELEPTY_SHA: ([0-9a-f]{40})/.exec(p)[1];
  const expected = `tested-compatibility-ubuntu-latest-node-20.20.0-telepty-${pin}`;
  assert.equal((p.match(/name: (\S*compatibility-\S+)/g) || []).join("|"), `name: ${expected}`);
  assert.ok(/node: \["20\.20\.0"\]/.test(code) && /ubuntu-latest/.test(code));
});
