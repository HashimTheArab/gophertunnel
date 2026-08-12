# One-Shot Protocol Update Checklist

Run this before the first edit and against the final `merge-base...HEAD` diff. Mark an item N/A only when its wire/API
shape is absent from the update.

## Target and branch

- [ ] Confirm the requested Minecraft version, network protocol, exact BDS build, and gophertunnel base branch.
- [ ] Fetch the base and branch from its current tip; record the merge-base SHA.
- [ ] Start from `git status --short --branch`; preserve unrelated user changes.
- [ ] Treat supplied patches and old PR branches as evidence. Inventory their files and reapply only target-relevant work.
- [ ] Verify protocol/version constants, packet IDs, pool direction/registration, and removed packet registrations.
- [ ] Search for stale protocol numbers and version-specific branches after implementation.

## Evidence ledger

- [ ] Pin Mojang docs, bpd-fixer, Cloudburst, PMMP, symbols, and other references to commits/builds.
- [ ] Classify Mojang artifacts by internal changelog/schema metadata, not filenames or PR labels.
- [ ] Build bpd-fixer for the matching docs ref and inspect `output/json` serialization options.
- [ ] Trace the exact Cloudburst codec, inherited serializer/helper, type maps, and both read/write paths.
- [ ] Distinguish engine/internal enums and registries from packet-facing numeric values.
- [ ] Record old shape, target shape, read evidence, write evidence, conflicts, and resolution for every changed field.
- [ ] Resolve a source conflict with exact target BDS/client bytes; do not pick the most convenient implementation.
- [ ] Record BDS version/build/checksum and inspect raw disputed primitives without the constants under test.
- [ ] Require positive target evidence before changing an existing field's type/width/order.

## Wire audit: every changed packet and shared type

- [ ] Compare all fields in ordinal order, including unchanged neighbors around insertions/removals.
- [ ] Verify fixed versus varint, signedness/zigzag, compression, width, and endianness independently.
- [ ] Resolve actor unique ID versus runtime ID semantically; use the appropriate semantic IO method and exact suffix.
- [ ] Verify colour channel semantics separately from integer endianness.
- [ ] Model every independent presence bool as `Optional[T]`; preserve present-zero and present-empty.
- [ ] Model `bool + optional` as `DoubleOptionalFunc`; outer absence consumes no inner marker.
- [ ] Do not derive independent presence from values, nil slices, action kinds, or another payload field.
- [ ] Derive duplicated discriminator metadata from one state only when exact evidence proves it is duplicated metadata.
- [ ] Consume ignored/reserved fields at exact width/order without exposing state or inventing validation.
- [ ] Verify every union/`oneOf` selector, complete variant range, skipped ordinals, and payload field order.
- [ ] If a decoded enum is one above the known range, verify missing zero sentinels and raw bytes before blaming alignment or a cache branch.
- [ ] Distinguish variant selectors, type values, enum indexes, postfix indexes, and flag-combined descriptors.
- [ ] Verify all collection count widths, element order, maps as key/value entries, and fixed cardinalities.
- [ ] Validate unknown values only as strictly as the exact target reader; canonical writer form is not a decoder invariant.
- [ ] Check sentinel bounds and request modes against the target; remove invalid old sentinels and their consumers.
- [ ] Confirm absent/inactive branches do not mutate caller-owned packets in shared read/write `Marshal` code.
- [ ] Confirm fresh decode allocation already handles stale state before adding manual clearing logic.

## Go API and gophertunnel consistency

- [ ] Search sibling packets/types before introducing a representation, helper, name table, or validation pattern.
- [ ] Choose the best target-version public type first; do not preserve an inferior type for API compatibility.
- [ ] Use `IntegerFunc` only for a deliberate semantic-type/wire-type difference, never as cast scaffolding.
- [ ] Use existing `IO`, optional, slice, fixed-count, and integer helpers instead of hand-rolled equivalents.
- [ ] Put cross-packet semantic primitives on `IO`/`Reader`/`Writer`; update both directions and interface together.
- [ ] Put a reusable public protocol type's codec on its exported `Marshal(IO)` method.
- [ ] Export stable direction-agnostic primitives; keep packet selectors, tables, validation, and adapters private.
- [ ] Remove packet-specific wrappers around an already-complete generic constructor/helper.
- [ ] For small wire-list sets, preserve absent/present-empty and uniqueness with a list-backed abstraction, not a map.
- [ ] Keep a public trailing `...Count` enumerator in its constant block only when callers need the valid range.
- [ ] Use arrays when exact fixed cardinality materially improves the API; do not churn established slices without value.
- [ ] Keep dense one-use name tables local and bounds-checked; use switches/maps for sparse mappings.
- [ ] Use `iota` for ordered ranges, `_` for reserved slots, explicit values for sparse/high-bit constants.
- [ ] Never expose only the new suffix of an otherwise unexposed enum; ask whether to omit or add the complete enum, then prefer its existing owning file/block.
- [ ] Document exported semantics and non-obvious invariants; delete comments that restate private code or release history.
- [ ] Remove unused helpers, IO entries, caches, aliases, compatibility fields, duplicate models, and reconstruction logic.

## Scope and generated artifacts

- [ ] Classify every final changed file as required protocol, required shared abstraction, required generated output, or remove it.
- [ ] Move unrelated NBT, reader/writer, refactor, and bug-fix work to separate PRs.
- [ ] Remove all backward-compatible branches, aliases, fallback serializers, and old/new representations.
- [ ] Change canonical generator inputs, regenerate, and verify a second run is clean.
- [ ] Do not commit BDS binaries, symbols, packet captures, conversion scratch files, or debug instrumentation.
- [ ] Require no new test files/cases in Hashim's PR unless explicitly requested; inspect all `*_test.go`, `go.mod`, and `go.sum` drift.
- [ ] Search gophertunnel, Dragonfly, Lunar, and other known consumers for every changed exported symbol.

## Verification and live behavior

- [ ] Run `gofmt` on changed Go files and `git diff --check`.
- [ ] Run `go test ./minecraft/protocol` and `go test ./minecraft/protocol/packet`.
- [ ] Run `go test ./... -count=1`, `go vet ./...`, and CI-equivalent checks when shared behavior/API changes.
- [ ] If committed tests are forbidden, delete any temporary fail/pass test before staging and recheck the diff.
- [ ] Build each affected downstream against the exact commit/pseudo-version being claimed.
- [ ] Exercise the actual changed feature path with the exact client/server, not only login/spawn.
- [ ] Check both sides for unread bytes, unknown packets/enums, invalid values, panics, kicks, and silent semantic failure.
- [ ] Remember that generic bots may not request sub-chunks, validate palettes, send inventory variants, or render debug shapes.
- [ ] Repeat a representative clean connection/reconnect and record versions, path, command, and result.

## PR and downstream closeout

- [ ] Inspect the complete final diff and changed-file list before staging; stage only intended files.
- [ ] Use normal follow-up commits, no Codex attribution, no amend unless asked, and never force-push unless asked.
- [ ] Open ready for review with pinned sources, evidence conflicts, checks, live validation, and test-file status.
- [ ] Fetch the created PR body and verify real Markdown newlines rather than literal `\n`.
- [ ] Compare fork and upstream merge-base deltas; do not carry fork-only divergence into the upstream PR.
- [ ] Do not post unsolicited self-review/audit comments. Obey any instruction to inspect/fix without replying.
- [ ] When replies are authorized, verify every reply is public/submitted before resolving its thread.
- [ ] After every push, wait for refreshed checks and review bots; re-audit current unresolved actionable threads.
- [ ] Use temporary downstream fork `replace` directives only while upstream is unmerged.
- [ ] After upstream merges, update to the upstream pseudo-version, remove the replace, tidy, retest, and push consumers.
- [ ] Confirm Lunar points at the tested latest gophertunnel and Dragonfly commits and live-test the real Lunar path.

## Stop conditions

Do not merge or claim completion while any of these remains:

- unresolved source disagreement on a changed wire field;
- an unexplained file in the PR delta;
- incomplete public enum exposure;
- backward-compatibility or temporary debug path;
- downstream test using a different dependency commit than claimed;
- temporary fork `replace` after upstream merge;
- pending/unsubmitted reply, failing check, or unresolved current actionable review thread.
