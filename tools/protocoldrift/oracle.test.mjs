import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { loadConfig, readOracleIdentity, validateComparison } from "./oracle.mjs";

// fixture creates a tiny committed oracle so validation never needs the network.
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "protocol-drift-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, "README.md"), "**Minecraft Version:** 9.8.7.6 (stable)\n**Network Version:** 12345\n");
  for (const directory of ["packets", "types", "enums"]) {
    fs.mkdirSync(path.join(root, directory));
    fs.writeFileSync(path.join(root, directory, "fixture.json"), "{}");
  }
  git(root, "init", "--quiet");
  git(root, "add", ".");
  git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture");
  const config = {
    minecraft_version: "9.8.7", protocol_version: 12345, packets: [],
    oracle: { repository: "https://example.invalid/oracle.git", revision: git(root, "rev-parse", "HEAD"), minecraft_version: "9.8.7.6" },
  };
  return { root, config, flat: { minecraft_version: "9.8.7", protocol_version: 12345 } };
}

// git runs fixture commands without using the shell or a user's Git identity.
function git(root, ...args) {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

test("exact BDS build and compatibility label remain distinct", (t) => {
  const { root, config, flat } = fixture(t);
  assert.deepEqual(validateComparison(flat, config, root), { ...config.oracle, protocol_version: 12345 });
});

test("comparison rejects source version and protocol mismatches before opening an oracle", (t) => {
  const { config, flat } = fixture(t);
  for (const mismatch of [{ ...flat, protocol_version: 12344 }, { ...flat, minecraft_version: "9.8.6" }, {}]) {
    assert.throws(() => validateComparison(mismatch, config, "/missing-oracle"), /inspected source target/);
  }
});

test("oracle identity rejects a different commit, build or protocol", (t) => {
  const { root, config } = fixture(t);
  assert.throws(() => readOracleIdentity(root, { ...config, oracle: { ...config.oracle, revision: "0".repeat(40) } }), /revision/);
  assert.throws(() => readOracleIdentity(root, { ...config, oracle: { ...config.oracle, minecraft_version: "9.8.7.5" } }), /target/);
  assert.throws(() => readOracleIdentity(root, { ...config, protocol_version: 12344 }), /target/);
  assert.throws(() => readOracleIdentity(path.join(root, "packets"), config), /root of its own/);
});

test("oracle identity rejects edited, deleted and untracked input files", (t) => {
  const { root, config } = fixture(t);
  const tracked = path.join(root, "packets/fixture.json");
  fs.writeFileSync(tracked, '{"name":"changed"}');
  assert.throws(() => readOracleIdentity(root, config), /modified or untracked/);
  fs.unlinkSync(tracked);
  assert.throws(() => readOracleIdentity(root, config), /modified or untracked/);
  git(root, "checkout", "--", "packets/fixture.json");
  fs.writeFileSync(path.join(root, "types/extra.json"), "{}");
  assert.throws(() => readOracleIdentity(root, config), /modified or untracked/);
});

test("config rejects absent oracle pins and moving revisions", (t) => {
  const { root, config } = fixture(t);
  const file = path.join(root, "config.json");
  for (const oracle of [undefined, { ...config.oracle, revision: "r26_u5" }, { ...config.oracle, repository: "http://example.invalid/repo" }, { ...config.oracle, minecraft_version: "9.8.7" }]) {
    fs.writeFileSync(file, JSON.stringify({ ...config, oracle }));
    assert.throws(() => loadConfig(file), /must pin/);
  }
  fs.writeFileSync(file, JSON.stringify(config));
  assert.deepEqual(loadConfig(file), config);
});

test("comparator CLI fails on stale extractor metadata", (t) => {
  const { root } = fixture(t);
  const flat = path.join(root, "flat.json");
  fs.writeFileSync(flat, JSON.stringify({ minecraft_version: "1.26.40", protocol_version: 2168, packets: [] }));
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./compare.mjs", import.meta.url)), "/missing-oracle", flat], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /inspected source target/);
});

test("committed oracle record is complete", () => {
  assert.ok(loadConfig().oracle.revision);
});
