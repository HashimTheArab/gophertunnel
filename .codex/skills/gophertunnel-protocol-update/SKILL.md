---
name: gophertunnel-protocol-update
description: Use when updating, reviewing, or debugging gophertunnel for a new Minecraft Bedrock protocol version, especially packet codecs, protocol constants, Cloudburst/PMMP/Mojang doc comparisons, live packet decode errors, or PR preparation for HashimTheArab/gophertunnel.
---

# Gophertunnel Protocol Update

## Goal

Update gophertunnel protocol code from scratch with source-backed evidence. Prefer correct wire compatibility over matching any single upstream implementation.

## Source Order

1. Identify the exact target protocol and Minecraft version first.
2. Check Mojang `bedrock-protocol-docs` for current schemas and `x-ordinal-index` order.
3. Check Cloudburst for the exact target codec version and packet serializer.
4. Check PMMP BedrockProtocol current implementation for independent codec evidence.
5. Use LeviLamina/BDS symbols for C++ field names and layout hints, but verify that the commit matches the target protocol before treating it as current.
6. Use live BDS/client packet bytes when sources disagree or decode still fails.

Do not pull changes from earlier protocol updates by accident. Cloudburst often updates previous codec classes too; verify that the class or registration is specifically used by the target protocol.

Pin every reference to a commit. If Mojang's current generated schema names a different protocol or Minecraft version than the target, disclose the conflict and use the exact-version implementation for wire behavior; do not silently mix releases.

### bpd-fixer

Use [TwistedAsylumMC/bpd-fixer](https://github.com/TwistedAsylumMC/bpd-fixer) as a corrected view of Mojang schemas, not as a replacement for exact-version codec evidence. After selecting the matching `bedrock-protocol-docs` ref:

```bash
git submodule update --init --recursive
npm install
npm run build:schemas  # corrected schemas in output/json
npm run check
```

Inspect `output/json`, especially `x-serialization-options`. The `+double-optional` marker means `bool + (bool + value-if-true)`. Stale overrides failing after a protocol bump are evidence to investigate, not errors to bypass.

## Cross-Check Rules

- Treat Cloudburst read and write paths as separate evidence. If they differ, do not blindly copy the write path; for gophertunnel decode correctness, the read path and live payloads are usually more important.
- Treat Mojang docs as high-value for field order and logical types, but not infallible. Confirm with at least one implementation or live bytes for risky changes.
- Read a schema field's name, prose description, `$ref`, serialization metadata, and changelog as separate evidence. If
  the description or field name conflicts with `$ref`, do not automatically privilege the reference. Trace the field
  back to its first appearance, then check an independent exact-version serializer or live bytes. A generated-schema
  refactor that carries the same contradiction from DOT into JSON is not evidence that the wire type changed.
- Treat PMMP as strong independent evidence when it matches Mojang docs or live bytes, even if Cloudburst differs.
- Trace the exact serializer registered by the target codec, including inherited serializers and helpers. Do not infer
  wire encoding from a nearby enum map, type registry, or newer serializer alone: a registry may only translate a value
  to its serialized name. For protocol 2168, `LevelSoundEvent` still writes that name as a string even though Cloudburst
  supplies an exact-version sound-event map.
- For `map<K,V>` schemas, check the byte layout. A gophertunnel slice is fine if each entry serializes `key` then `value` in map order.
- For optional fields, preserve exact ordinal order. Missing an optional marker shifts all later fields.
- A wire presence bool that directly guards a value is an `Optional[T]` field. Marshal it with `OptionalFunc`,
  `OptionalMarshaler`, or the matching existing helper. Do not hand-write `hasX`, `Bool`, value, and absent-value
  clearing branches that merely reimplement `Optional`; the extra code hides the wire shape and easily loses states.
- Preserve present zero and present empty values. Never infer an independent optional's presence from `value != 0`,
  `slice != nil`, or another payload value. For protocol 2168, every optional in `SubChunkEntry`—raw payload, both
  height-map arrays, and blob hash—must use `Optional`, including `Optional[uint64]` so a present zero hash remains
  representable.
- Derive presence from an action/type discriminator only when the exact-version writer defines the bool as duplicated
  discriminator metadata rather than an independent optional. On read, validate that duplicated values agree. Do not
  use this exception for ordinary schema optionals.
- When the exact read path accepts a presence marker independently, represent that state with `Optional[T]` even if a
  reference writer normally chooses presence from another field. Do not collapse it into a plain value plus a custom
  action check unless the marker is proven to be duplicated discriminator metadata. This applies equally to nested
  structs such as map entries, scoreboard identity entries, and inventory transaction payloads.
- Do not derive wire optionality solely from a schema's `required` array. For protocol 2168,
  Mojang's `gatheringsConfig.json` marks all eight fields required and bpd-fixer currently leaves that unchanged,
  but Cloudburst's exact-version read/write codec shows that `worldId`, `worldName`, `targetId`, `scenarioId`, and
  `serverId` each carry an optional marker; only `experienceId`, `experienceName`, and `creatorId` are required.
  The containing gathering configuration is independently optional in Transfer and server join information.
- Cereal commonly duplicates compatibility metadata: a varuint selector plus a legacy byte, or an outer presence bool around a normal optional. Derive both copies from one value when writing; read and validate both when decoding unless the exact target codec documents a reserved constant that is intentionally ignored.
- The selector and the type byte it precedes are two different numberings. The selector indexes the variant list, which skips types that are no longer sent, while the type byte still counts them. Work out the mapping between the two and check it against the full enum before assuming they are equal; assuming so rejects every type above the first skipped one, and would read one as the type below it. Types no longer sent still occupy their numbers in the type byte, so keep them.
- When an outer optional is absent, do not consume its inner marker. Clear the destination value. More generally, every absent branch must clear stale slices, hashes, optionals, and IDs because packet structs may be reused.
- For `Compression` on enum/integer fields, the logical Go type may remain small (`byte`, enum) while the wire encoding uses varint/varuint.
- Distinguish actor unique IDs from runtime IDs:
  - actor unique ID: signed `varint64` zigzag
  - runtime entity ID: unsigned `varuint64`
  Use live bytes to resolve ambiguity.
- Resolve the semantic identifier before choosing the Go signedness or codec. Names such as `Attached To Entity ID` are
  insufficient by themselves; reconcile the field description, owning C++/implementation type, and actual serializer.
- PrimitiveShapes `PrimitiveShapeDataPayload.Attached To Entity ID` is a runtime actor ID on the wire. Mojang
  `bedrock-protocol-docs` has historically described it as runtime ID while linking the schema node to
  `ActorUniqueID`; trust the runtime-ID wording plus independent implementation/BDS evidence here. PMMP encodes
  this field with `getActorRuntimeId`/`putActorRuntimeId`, LeviLamina names the field
  `std::optional<ActorRuntimeID> mAttachedToId`, and live BDS ignored signed/unique-style encoding while accepting
  unsigned runtime encoding. In gophertunnel, model it as `Optional[uint64]` and marshal with `Varuint64`, not
  signed `Varint64`.
- For `oneOf`/variant selectors, encode the selector as documented, usually varuint, not as a bool unless the source explicitly says bool.
- Do not infer a `oneOf` selector from a field label or a broken reference implementation. For sound-data updates, verify the full selector range and every payload ordinal against the exact schema: the server sound handle is a fixed `uint64`, the action selector is a compressed `uint32`, and Fade carries duration before target volume. A serializer that always writes Stop or reverses Fade fields is evidence of an implementation bug, not a compatibility requirement.
- For enum sentinels like `UNDEFINED`, check whether they existed historically at changing numeric indexes before calling them a new semantic value.
- Re-derive sentinel-style modes from the exact-version schema instead of trusting constants retained from older releases. In protocol 2168, `LevelChunk.SubChunkCount` is constrained to `0..64`; request mode is `SubChunkCount == 0` with `SubChunkLimit` present (`-1` means limitless). Remove the invalid old `MaxUint32` count sentinels rather than deprecating them, and audit downstream emitters and consumers as well as the codec when a representation changes.
- When a release appends values to an enum that gophertunnel does not already expose completely, do not add only the new suffix. Ask the operator whether to omit the constants or expose the complete exact-version enum before changing the public API.
- For contiguous protocol constants, prefer the surrounding gophertunnel style. `iota` is fine for dense, ordered wire-value ranges when every value is consecutive and future additions can be inserted in order.
- Keep non-contiguous or out-of-band protocol values explicit. Use hex for flag-like/high-bit values such as `0x8000000`, and separate them from the contiguous `iota` block with a blank line.
- Never preserve a legacy path or backward-compatibility path, for any reason. The fork targets exactly one protocol. Remove old/new wire branches, fallback serializers, deprecated source aliases, parallel representations, and inert fields outright. Do not add multi-version behavior, and do not keep a branch because an older version needed it or a reference implementation still has one — a branch on a flag whose presence the wire already states is a legacy path, not a codec. Keep a legacy-named field only when the exact target still carries it on the wire, and rename it to what it is.
- Only change how a field is sent when there is positive evidence the target changed it. A field the previous version encoded one way is presumed unchanged; re-typing it on a hunch is a silent regression, because most re-typings are the same byte length for the values the field actually holds and so never desync. By the same token, a field that changes width keeps its component and field order unless the source says otherwise.
- Treat exact-version writer calls as width evidence. For example, `writeUnsignedInt` and `writeByte` are not
  interchangeable with signed varints merely because the current values are small; model and marshal the target width
  directly instead of retaining an old Go type and adding conversion scaffolding.

## Codebase Consistency

- Model the target wire shape once. Do not keep aggregate and typed representations that need synchronization, packet-level selectors when the selector moved per entry, or exported compatibility fields that are no longer encoded.
- Specialized descriptor-backed items must expose only their string identity and other wire-backed fields. Do not embed a broader numeric-ID item type and permit contradictory identities.
- Use existing `IO`, `Marshal`, `Slice`, `FuncSlice`, and optional helpers instead of parallel reader/writer trees or
  manual equivalents. If the wire shape is `bool + value-if-true`, the default representation is `Optional[T]` plus
  `OptionalFunc`; require exact-version evidence before writing a custom presence branch.
- Put stable, direction-agnostic wire primitives in `minecraft/protocol`, even when first discovered in one packet. For example, nested Cereal optionals belong beside `OptionalFunc` as `DoubleOptionalFunc`.
- Keep packet semantics private: selector-to-name conversions, one-packet union validation, recipe-family implementation helpers, and format-specific adapters should not become public APIs merely to shorten a packet file.
- Audit every new private helper before PR closeout. Export it only when the abstraction is protocol-generic and its name/contract remain meaningful outside the originating packet; otherwise keep it local.
- Remove dead lookups, duplicated codecs, inert fields, transitional caches, and write-then-reconstruct heuristics introduced by a broad patch.

## Implementation Workflow

1. Start with `git status --short --branch`; never revert unrelated user changes.
2. Gather references before editing. Capture commit SHAs or stable links for Mojang, Cloudburst, PMMP, and any LeviLamina/BDS evidence used.
3. Diff the current gophertunnel files against source evidence packet by packet.
4. Make the smallest coherent code change that fixes the target protocol. Avoid unrelated refactors and generated churn, but remove patch-introduced duplication or compatibility scaffolding before review.
5. Respect user-specific constraints. For Hashim's gophertunnel work, use normal follow-up commits, do not amend unless asked, do not add "committed by Codex", and do not add new test files when the user says tests are unnecessary. Mechanically migrate existing fixtures only when a required API change would otherwise leave the branch uncompilable.
6. Run targeted verification first:
   - `go test ./minecraft/protocol`
   - `go test ./minecraft/protocol/packet`
   - `git diff --check`
   Add `go test ./... -count=1`, `go vet ./...`, and repository CI-equivalent static checks when shared behavior changes.
   If the user forbids test files in the PR, temporary local regression tests are still useful: watch them fail, make them pass, then delete them before staging.
7. If Lunar or another downstream project consumes a pseudo-version branch, verify which branch/commit its `go.mod` points at before claiming live testing will include the new fix.
8. Push the requested branch only after tests pass and status is understood.
9. Before staging, inspect `git diff --name-only -- '*_test.go' go.mod go.sum`. When tests and dependency changes are out of scope, require it to be empty except for unavoidable mechanical migrations of existing fixtures; never add new test files under a no-tests constraint.

## Review Checklist

- Compare the exact-version read and write paths independently.
- Check field order, signedness, widths, selectors, legacy copies, optional nesting, slice lengths, and absent-state clearing.
- For every apparent enum change, confirm whether the registered serializer writes an ordinal, a name looked up from
  the enum, or both. Never infer the wire representation from the presence of an enum/type map.
- Audit every new `Bool`-guarded branch. Replace it with the existing optional helper unless the bool is proven to be
  duplicated discriminator metadata or has a different wire shape.
- Check that public structs contain only meaningful target-version state and that selector granularity matches the wire (packet, entry, or element).
- Run a protocol-correctness review against pinned references and a separate maintainability/API-consistency pass.
- When an independent Opus audit is requested, run it non-interactively with `claude -p --model opus`. Disable unrelated settings, plugins, and MCP servers when they would make print mode hang, and give the audit the committed diff plus exact-version evidence. Treat its findings as claims under the same source-validation rule.
- Treat bot findings as claims: validate them against the exact target. Fix real issues; reply with source-backed rebuttals for false positives and resolve the thread.
- After every push, wait for refreshed CI and review bots. Finish only when checks pass and no current unresolved actionable threads remain.

## Debugging Decode Errors

- Remember that a "remaining bytes" dump is often the unread tail after partial decode, not the full packet.
- When a packet leaves a large unread tail, first look for a missing field, missing optional marker, or wrong variant selector before assuming a nested type is corrupt.
- For repeated binary structures, compare field order from Mojang `x-ordinal-index`, PMMP read/write order, and Cloudburst read order.
- Add temporary packet logging only in the downstream/debug repo unless the user asks to keep it. Do not commit temporary live-capture instrumentation by default.

## PR Output

When asked for a PR description, include:

- concise summary of packet/codecs changed
- exact source links per change
- test commands run
- known evidence conflicts, if any
- the explicit absence of new test files when requested

Use direct GitHub links with commit SHAs where possible.
Use real Markdown newlines; after creation, fetch the body and verify it does not contain literal `\n` escapes. Open ready for review unless the user asks for a draft. For an upstream PR, use the fork branch as the head and the upstream default branch as the base; never force-push.
