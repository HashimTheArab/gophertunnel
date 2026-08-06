// Compares gophertunnel's packet encodings against schemas extracted from a
// running Bedrock Dedicated Server, and fails on drift that is not explicitly
// accepted.
//
// The oracle is endstonemc/protocol-docs, produced by protocol-dumper reading
// a live BDS. It therefore describes what the server actually serialises,
// which is a different and stronger claim than what documentation asserts.
//
// Usage:
//   go run ./tools/protocoldrift .            # writes gophertunnel-flat.json
//   node tools/protocoldrift/compare.mjs <endstone-docs-dir> [flat.json]

import fs from "node:fs";
import path from "node:path";

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/(.:)/, "$1"));
const docsDir = process.argv[2];
const flatPath = process.argv[3] ?? "gophertunnel-flat.json";

if (!docsDir) {
  console.error("usage: node compare.mjs <endstone-docs-dir> [gophertunnel-flat.json]");
  process.exit(2);
}

// ---------------------------------------------------------------------------
// endstone corpus -> flattened primitive operations
// ---------------------------------------------------------------------------

// `varint*` is zigzag-signed and `uvarint*` is unsigned. Conflating them is a
// silent wire corruption, so they stay distinct all the way through.
const SCALARS = {
  bool: "Bool",
  uint8: "U8", int8: "I8",
  uint16: "U16LE", int16: "I16LE",
  uint32: "U32LE", int32: "I32LE",
  uint64: "U64LE", int64: "I64LE",
  int32_be: "I32BE",
  float: "F32LE", double: "F64LE",
  varint32: "ZigZag32", varint64: "ZigZag64",
  uvarint32: "VarInt", uvarint64: "VarLong",
};

// Named types whose wire form is a single primitive, preferred over any
// same-named document.
const BUILTIN = { CompoundTag: "Nbt", "mce::UUID": "Uuid" };

function loadDir(sub) {
  const dir = path.join(docsDir, sub);
  const out = new Map();
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const doc = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
    // Names are read from the document: `::` becomes `__` in filenames.
    if (doc.name) out.set(doc.name, doc);
  }
  return out;
}

const packets = loadDir("packets");
const types = loadDir("types");
const enums = loadDir("enums");

const unresolved = [];

function lowerRepeat(repeat, inner, ctx) {
  if (repeat?.prefix) {
    const prefix = SCALARS[repeat.prefix];
    if (!prefix) { unresolved.push(`${ctx}: unknown repeat prefix ${repeat.prefix}`); return null; }
    return { kind: "array", prefix, element: inner };
  }
  if (typeof repeat?.count === "number") return { kind: "fixed_array", length: repeat.count, element: inner };
  unresolved.push(`${ctx}: repeat has neither prefix nor count`);
  return null;
}

function lowerType(ty, ctx, active) {
  if (typeof ty === "string") {
    if (ty === "string") return { kind: "string", prefix: "VarInt", encoding: "utf8" };
    if (SCALARS[ty]) return { kind: "primitive", op: SCALARS[ty] };
    if (BUILTIN[ty]) return { kind: "primitive", op: BUILTIN[ty] };
    const doc = types.get(ty);
    if (!doc) {
      // The corpus references two names it never defines; both are recorded
      // rather than guessed at.
      if (ty.startsWith("brstd::bitset<")) return { kind: "array", prefix: "VarInt", element: [{ kind: "primitive", op: "U8" }] };
      if (ty === "cereal::DynamicValue") return { kind: "unresolved", reason: "cereal::DynamicValue is not defined by the corpus" };
      unresolved.push(`${ctx}: unknown type ${ty}`);
      return { kind: "unresolved", reason: `unknown type ${ty}` };
    }
    if (active.has(ty)) return { kind: "recursive_reference", type_name: ty };
    active.add(ty);
    const fields = lowerFields(doc.fields ?? [], ty, active);
    active.delete(ty);
    return fields;
  }
  if (!ty || typeof ty !== "object") { unresolved.push(`${ctx}: malformed type`); return { kind: "unresolved", reason: "malformed type" }; }

  if (ty.switch) {
    const control = SCALARS[ty.switch.type];
    if (!control) { unresolved.push(`${ctx}: unknown switch discriminant ${ty.switch.type}`); return { kind: "unresolved", reason: "switch discriminant" }; }
    const cases = ty.cases ?? [];
    return {
      kind: "union",
      op: control,
      value: cases.map((c, i) =>
        c === null ? { kind: "primitive", op: "Void" } : flatten(lowerType(c, `${ctx}[case ${i}]`, active))),
    };
  }
  if (ty.key !== undefined && ty.value !== undefined) {
    // A map is a length-prefixed array of key/value entries.
    return {
      kind: "array", prefix: "VarInt",
      element: [flatten(lowerType(ty.key, `${ctx}.key`, active)), flatten(lowerType(ty.value, `${ctx}.value`, active))].flat(),
    };
  }
  if (ty.type !== undefined) {
    let inner = lowerType(ty.type, ctx, active);
    if (ty.repeat) inner = lowerRepeat(ty.repeat, flatten(inner), ctx) ?? inner;
    return inner;
  }
  unresolved.push(`${ctx}: unsupported type shape [${Object.keys(ty).join(", ")}]`);
  return { kind: "unresolved", reason: "unsupported type shape" };
}

function flatten(x) { return Array.isArray(x) ? x : [x]; }

function lowerFields(fields, ctx, active) {
  const out = [];
  for (const [i, field] of fields.entries()) {
    // A field with a literal value and no name is a constant written on the
    // wire (PlayerAuthInput's presence flag), so it occupies wire space.
    const name = field.name ?? `constant_${i}`;
    let lowered = flatten(lowerType(field.type, `${ctx}.${name}`, active));
    if (field.repeat) {
      const wrapped = lowerRepeat(field.repeat, lowered, `${ctx}.${name}`);
      lowered = wrapped ? [wrapped] : lowered;
    }
    if (field.optional === true) lowered = [{ kind: "option", presence: "Bool", value: lowered }];
    for (const op of lowered) out.push({ ...op, field: op.field ?? name });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

// Signed and unsigned fixed-width integers of the same width and endianness are
// the same bytes. Everything else stays distinct: width, endianness,
// fixed-vs-varint, varint-vs-zigzag and presence are all preserved.
const FIXED = new Map([
  ["I8", "F8"], ["U8", "F8"],
  ["I16LE", "F16LE"], ["U16LE", "F16LE"],
  ["I32LE", "F32I"], ["U32LE", "F32I"],
  ["I32BE", "F32BE"], ["U32BE", "F32BE"],
  ["I64LE", "F64I"], ["U64LE", "F64I"],
]);
const canon = (op) => FIXED.get(op) ?? op;

// gophertunnel writes a UUID as 16 raw bytes; the corpus names the type. Same
// 16 bytes at the same position, so both collapse to one token. Byte ORDER
// within the UUID is not checked by this comparison.
const UUID_TOKENS = 'Fixed[16 F8 ]';

// Several fields are NBT compounds the server hands over already encoded;
// gophertunnel writes those bytes verbatim with io.Bytes, while the corpus
// types them CompoundTag. Same bytes, different name.
const PREENCODED_NBT = /Serialised(?:Offers|InventoryData|EntityIdentifiers|EventData)$/;

function tokens(ops, acc = [], trail = "") {
  for (const op of ops ?? []) {
    switch (op.kind) {
      case "primitive":
        if (op.op === "Uuid") { acc.push(UUID_TOKENS); break; }
        // A pre-encoded NBT blob written verbatim is the same bytes as the
        // compound the corpus describes.
        if (op.op === "RawBytes" && PREENCODED_NBT.test(op.field ?? "")) { acc.push("Nbt"); break; }
        acc.push(canon(op.op));
        break;
      // A length-prefixed string and a length-prefixed byte slice are the same
      // bytes: the encoding does not transform the payload.
      case "string": acc.push(`Bytes:${op.prefix ?? "VarInt"}`); break;
      case "array": acc.push(`Array[${op.prefix}`); tokens(op.element, acc, trail); acc.push("]"); break;
      case "fixed_array": acc.push(`Fixed[${op.length}`); tokens(op.element, acc, trail); acc.push("]"); break;
      case "option": acc.push("Opt["); tokens(op.value, acc, trail); acc.push("]"); break;
      case "union": acc.push(`Union[${canon(op.op)}`); tokens(op.value, acc, trail); acc.push("]"); break;
      case "recursive_reference": acc.push(`Rec<${op.type_name}>`); break;
      default: acc.push(`UNRESOLVED(${op.reason ?? op.kind})`); break;
    }
  }
  return acc;
}

const flat = JSON.parse(fs.readFileSync(flatPath, "utf8"));
const byID = new Map((flat.packets ?? []).map((p) => [p.id, p]));

const baselinePath = path.join(here, "accepted-drift.json");
let baseline = { packets: [] };
try { baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8")); }
catch { console.error(`no accepted-drift.json beside compare.mjs; refusing to pass silently`); process.exit(1); }
const accepted = new Map((baseline.packets ?? []).map((p) => [p.id, p]));

const rows = [];
for (const [name, doc] of packets) {
  if (typeof doc.id !== "number") continue;
  const oracle = byID.get(doc.id);
  if (!oracle) { rows.push({ id: doc.id, name, status: "NO_GOPHERTUNNEL_PACKET" }); continue; }

  const before = unresolved.length;
  const ours = tokens(lowerFields(doc.fields ?? [], name, new Set()));
  const theirs = tokens(oracle.operations);

  const eitherUnresolved =
    unresolved.length !== before ||
    ours.some((t) => t.startsWith("UNRESOLVED")) ||
    theirs.some((t) => t.startsWith("UNRESOLVED"));

  if (eitherUnresolved) { rows.push({ id: doc.id, name, status: "UNRESOLVED" }); continue; }
  rows.push({
    id: doc.id, name,
    status: ours.join(" ") === theirs.join(" ") ? "AGREEMENT" : "DRIFT",
    bds: ours, gophertunnel: theirs,
  });
}

const counts = {};
for (const r of rows) counts[r.status] = (counts[r.status] ?? 0) + 1;
const drift = rows.filter((r) => r.status === "DRIFT");

fs.writeFileSync(path.join(here, "drift-report.json"), JSON.stringify({ counts, rows }, null, 2) + "\n");

console.log(JSON.stringify(counts, null, 2));
for (const r of drift) {
  const mark = accepted.has(r.id) ? "accepted" : "NEW";
  console.log(`\n[${mark}] ${r.id} ${r.name}`);
  if (!accepted.has(r.id)) {
    console.log(`  bds:          ${r.bds.join(" ").slice(0, 300)}`);
    console.log(`  gophertunnel: ${r.gophertunnel.join(" ").slice(0, 300)}`);
  }
}

const unexpected = drift.filter((r) => !accepted.has(r.id));
const healed = [...accepted.keys()].filter((id) => !drift.some((r) => r.id === id));
for (const id of healed) console.warn(`note: packet ${id} no longer drifts; drop it from accepted-drift.json`);

if (unexpected.length) {
  console.error(`\nFAIL: ${unexpected.length} packet(s) drift from the BDS-derived schemas and are not accepted.`);
  console.error("Each is a candidate encoding bug. Verify against the server, fix the packet,");
  console.error("or add it to accepted-drift.json with a reason.");
  process.exit(1);
}
console.log("\nprotocol drift check: OK");
