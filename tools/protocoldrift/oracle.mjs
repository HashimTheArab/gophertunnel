import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const configPath = fileURLToPath(new URL("./accepted-drift.json", import.meta.url));

// loadConfig reads the shared comparison target, oracle pin and reviewed drift.
export function loadConfig(file = configPath) {
  const config = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!/^\d+\.\d+\.\d+$/.test(config.minecraft_version ?? "") ||
      !Number.isSafeInteger(config.protocol_version) || config.protocol_version <= 0 ||
      !Array.isArray(config.packets)) {
    throw new Error("accepted-drift.json must declare a compatibility version, positive protocol and packet list");
  }
  const oracle = config.oracle;
  if (!oracle || !/^https:\/\/[^\s]+$/.test(oracle.repository ?? "") ||
      !/^[0-9a-f]{40}$/.test(oracle.revision ?? "") ||
      !/^\d+\.\d+\.\d+\.\d+$/.test(oracle.minecraft_version ?? "")) {
    throw new Error("accepted-drift.json must pin an HTTPS oracle repository, full Git revision and exact BDS build");
  }
  return config;
}

// git reads a checkout without invoking a shell or accepting command fragments.
function git(directory, ...args) {
  const env = { ...process.env };
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE"]) delete env[key];
  return execFileSync("git", ["-C", directory, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env }).trim();
}

// readOracleIdentity verifies that the compared files belong to the pinned dump.
export function readOracleIdentity(directory, config) {
  const root = fs.realpathSync(directory);
  if (fs.realpathSync(git(root, "rev-parse", "--show-toplevel")) !== root) {
    throw new Error("schema oracle must be the root of its own Git checkout");
  }
  const revision = git(root, "rev-parse", "--verify", "HEAD");
  if (revision !== config.oracle.revision) {
    throw new Error(`schema oracle revision ${revision} does not match pinned ${config.oracle.revision}`);
  }
  if (git(root, "status", "--porcelain", "--untracked-files=all", "--", "README.md", "packets", "types", "enums")) {
    throw new Error("schema oracle has modified or untracked input files; use a clean pinned checkout");
  }
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  const versions = [...readme.matchAll(/\*\*Minecraft Version:\*\*[ \t]*`?(\d+\.\d+\.\d+\.\d+)`?(?=[ \t\r\n]|$)/g)];
  const protocols = [...readme.matchAll(/\*\*Network Version:\*\*[ \t]*`?(\d+)`?(?=[ \t\r\n]|$)/g)];
  if (versions.length !== 1 || protocols.length !== 1) {
    throw new Error("schema oracle README must declare exactly one Minecraft build and network version");
  }
  const minecraftVersion = versions[0][1];
  const protocolVersion = Number(protocols[0][1]);
  if (minecraftVersion !== config.oracle.minecraft_version || protocolVersion !== config.protocol_version) {
    throw new Error(`schema oracle target ${minecraftVersion}/${protocolVersion} does not match pinned ${config.oracle.minecraft_version}/${config.protocol_version}`);
  }
  return { repository: config.oracle.repository, revision, minecraft_version: minecraftVersion, protocol_version: protocolVersion };
}

// validateComparison rejects mismatched targets before any packet is compared.
export function validateComparison(flat, config, directory) {
  if (flat.minecraft_version !== config.minecraft_version || flat.protocol_version !== config.protocol_version) {
    throw new Error(`inspected source target ${flat.minecraft_version}/${flat.protocol_version} does not match accepted drift target ${config.minecraft_version}/${config.protocol_version}`);
  }
  return readOracleIdentity(directory, config);
}

// checkoutOracle fetches the single immutable pin into a new local directory.
function checkoutOracle(directory) {
  const config = loadConfig();
  fs.mkdirSync(directory);
  git(directory, "init", "--quiet");
  git(directory, "remote", "add", "origin", config.oracle.repository);
  git(directory, "fetch", "--quiet", "--depth", "1", "origin", config.oracle.revision);
  git(directory, "checkout", "--quiet", "--detach", "FETCH_HEAD");
  readOracleIdentity(directory, config);
  console.log(`schema oracle: BDS ${config.oracle.minecraft_version}, protocol ${config.protocol_version}, ${config.oracle.revision}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] !== "checkout" || !process.argv[3] || process.argv.length !== 4) {
      throw new Error("usage: node tools/protocoldrift/oracle.mjs checkout <new-directory>");
    }
    checkoutOracle(process.argv[3]);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
