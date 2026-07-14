# Moon Protocol Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the reviewed Moon gophertunnel protocol fixes to the `lunar` branch without merging unrelated Moon history.

**Architecture:** Keep each change at its existing ownership boundary: command wire constants in `protocol`, packet limits and direction registration in `packet`, and allocation guards in `nbt`. Use the exact current Bedrock wire values and intentionally remove the obsolete `CommandArgTypeValue` compatibility name.

**Tech Stack:** Go 1.25+, gophertunnel protocol codecs, Go testing.

## Global Constraints

- Target Minecraft Bedrock 1.26.30 / protocol 1001.
- Do not merge unrelated authentication, login, P2P, or dependency changes from Moon main.
- Backwards source compatibility for `CommandArgTypeValue` is not required.
- Push the verified result directly to `origin/lunar`.

---

### Task 1: Command argument wire values

**Files:**
- Modify: `minecraft/protocol/command_test.go`
- Modify: `minecraft/protocol/command.go`

**Interfaces:**
- Produces: `CommandArgTypeFloat == 3` and `CommandArgTypeRValue == 4` with no `CommandArgTypeValue` symbol.

- [x] Change the command constant test to expect float wire ID 3 and remove the obsolete value assertion.
- [x] Run `go test ./minecraft/protocol -run TestCommandArgTypeWireValues` and confirm it fails on float ID 2.
- [x] Reserve wire ID 2 in the `iota` block and remove `CommandArgTypeValue`.
- [x] Re-run the focused protocol test and confirm it passes.

### Task 2: Packet validation and direction fixes

**Files:**
- Create: `minecraft/protocol/packet/protocol_limits_test.go`
- Modify: `minecraft/protocol/packet/text.go`
- Modify: `minecraft/protocol/packet/network_chunk_publisher_update.go`
- Modify: `minecraft/protocol/packet/pool.go`

**Interfaces:**
- Produces: a 65,536-byte Text message is accepted, a 65,537-byte message is rejected, saved chunk lists over 9,216 entries are rejected, and `IDUpdateBlock` exists in `NewClientPool()`.

- [x] Add focused failing tests for the three packet behaviors.
- [x] Run the focused packet tests and confirm the missing validations/registration fail.
- [x] Add the Text maximum, explicit uncompressed saved-chunk count validation, and client packet registration.
- [x] Re-run the focused packet tests and confirm they pass.

### Task 3: NBT allocation guards

**Files:**
- Create: `minecraft/nbt/decode_limits_test.go`
- Modify: `minecraft/nbt/decode.go`

**Interfaces:**
- Produces: byte arrays and byte lists whose declared lengths exceed the remaining buffer return `BufferOverrunError` before allocation.

- [x] Add failing decode tests with impossible byte-array and byte-list lengths.
- [x] Run the focused NBT tests and confirm they fail with allocation-caused behavior rather than `BufferOverrunError`.
- [x] Add a remaining-buffer guard before byte-array and byte-list allocations.
- [x] Re-run the focused NBT tests and confirm they pass.

### Task 4: Verification and publication

**Files:**
- Review all modified files above.

**Interfaces:**
- Produces: one verified commit pushed to `origin/lunar`.

- [x] Run `gofmt` on changed Go files.
- [x] Run `go test ./minecraft/protocol`.
- [x] Run `go test ./minecraft/protocol/packet`.
- [x] Run `go test ./minecraft/nbt`.
- [x] Run `go test ./...`, `go vet ./...`, and `git diff --check`.
- [x] Run Codex review and adjudicate any actionable findings.
- [ ] Commit only the scoped files and push `lunar` to `origin/lunar`.
