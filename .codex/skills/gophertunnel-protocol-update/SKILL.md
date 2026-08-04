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
- Treat PMMP as strong independent evidence when it matches Mojang docs or live bytes, even if Cloudburst differs.
- For `map<K,V>` schemas, check the byte layout. A gophertunnel slice is fine if each entry serializes `key` then `value` in map order.
- For optional fields, preserve exact ordinal order. Missing an optional marker shifts all later fields.
- Do not derive wire optionality solely from a schema's `required` array. For protocol 2168,
  Mojang's `gatheringsConfig.json` marks all eight fields required and bpd-fixer currently leaves that unchanged,
  but Cloudburst's exact-version read/write codec shows that `worldId`, `worldName`, `targetId`, `scenarioId`, and
  `serverId` each carry an optional marker; only `experienceId`, `experienceName`, and `creatorId` are required.
  The containing gathering configuration is independently optional in Transfer and server join information.
- Cereal commonly duplicates compatibility metadata: a varuint selector plus a legacy byte, or an outer presence bool around a normal optional. Derive both copies from one value when writing; read and validate both when decoding unless the exact target codec documents a reserved constant that is intentionally ignored.
- When an outer optional is absent, do not consume its inner marker. Clear the destination value. More generally, every absent branch must clear stale slices, hashes, optionals, and IDs because packet structs may be reused.
- For `Compression` on enum/integer fields, the logical Go type may remain small (`byte`, enum) while the wire encoding uses varint/varuint.
- Distinguish actor unique IDs from runtime IDs:
  - actor unique ID: signed `varint64` zigzag
  - runtime entity ID: unsigned `varuint64`
  Use live bytes to resolve ambiguity.
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
- For contiguous protocol constants, prefer the surrounding gophertunnel style. `iota` is fine for dense, ordered wire-value ranges when every value is consecutive and future additions can be inserted in order.
- Keep non-contiguous or out-of-band protocol values explicit. Use hex for flag-like/high-bit values such as `0x8000000`, and separate them from the contiguous `iota` block with a blank line.
- Do not preserve backward-compatibility paths in a single-version protocol update. Remove old/new wire branches, fallback serializers, deprecated source aliases, parallel representations, and inert fields. Keep legacy-named fields only when the exact target still carries them on the wire. Add multi-version behavior only when the user explicitly requests it.

## Codebase Consistency

- Model the target wire shape once. Do not keep aggregate and typed representations that need synchronization, packet-level selectors when the selector moved per entry, or exported compatibility fields that are no longer encoded.
- Specialized descriptor-backed items must expose only their string identity and other wire-backed fields. Do not embed a broader numeric-ID item type and permit contradictory identities.
- Prefer existing `IO`, `Marshal`, `Slice`, `FuncSlice`, and `OptionalFunc` patterns over parallel reader/writer switch trees.
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
