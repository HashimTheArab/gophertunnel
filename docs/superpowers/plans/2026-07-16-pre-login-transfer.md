# Pre-login Transfer Handling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make pre-login Bedrock transfers observable as structured dial errors and validate the behavior against Zeqa.

**Architecture:** `minecraft.Conn.handle` recognizes `packet.IDTransfer` only while login is incomplete, decodes it using the active protocol, and returns a typed error. `DialContextNetwork` retains its existing connection cleanup and `net.OpError` wrapping. Transfer-follow policy remains outside the library.

**Tech Stack:** Go, gophertunnel Minecraft protocol, `net.Pipe`, Go testing.

## Global Constraints

- Target the `lunar` branch through `zeqa-patch`.
- Preserve typed protocol state instead of string matching.
- Do not add automatic reconnect policy to gophertunnel.
- Use a bounded transfer-follow loop for live validation only.

---

### Task 1: Pre-login transfer result

**Files:**
- Modify: `minecraft/dial_test.go`
- Modify: `minecraft/conn.go`
- Modify: `minecraft/err.go`

**Interfaces:**
- Consumes: `packet.Transfer`, `Conn.handle`, and existing dial error wrapping.
- Produces: `type TransferError struct { Address string; Port uint16; ReloadWorld bool }`.

- [ ] **Step 1: Write the failing transfer test**

Add a scripted `net.Pipe` server that completes network settings, sends `packet.Transfer{Address: "hub.zeqa.net", Port: 19133, ReloadWorld: true}` before login completes, and requires `errors.As(err, new(*TransferError))` with matching fields.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `go test ./minecraft -run TestDialContextReturnsPreLoginTransferError -count=1`

Expected: FAIL because `TransferError` is undefined or the dial reaches its deadline.

- [ ] **Step 3: Implement the typed result**

Add `TransferError` to `minecraft/err.go`. In `Conn.handle`, decode `packet.IDTransfer` before expected-packet filtering when `!conn.loggedIn`, then return the typed error with all packet fields.

- [ ] **Step 4: Add and run the ordinary-login guard**

Add a scripted successful login test and run: `go test ./minecraft -run 'TestDialContext(ReturnsPreLoginTransferError|OrdinaryLoginStillCompletes)' -count=1`.

Expected: PASS.

- [ ] **Step 5: Run package and repository verification**

Run: `gofmt -w minecraft/conn.go minecraft/dial_test.go minecraft/err.go`, `go test ./minecraft`, and `go test ./...`.

Expected: all commands exit 0.

### Task 2: Duplicate login-success handling

**Files:**
- Modify: `minecraft/dial_test.go`
- Modify: `minecraft/conn.go`

**Interfaces:**
- Consumes: `packet.PlayStatusLoginSuccess` during the client login state machine.
- Produces: idempotent handling after the first successful login status.

- [ ] **Step 1: Write and prove the failing regression**

Complete normal login and resource-pack negotiation in the scripted server, then send another `PlayStatusLoginSuccess` between `ItemRegistry` and `ChunkRadiusUpdated`. Run `go test ./minecraft -run TestDialContextIgnoresDuplicateLoginSuccess -count=1` and expect dial not to complete.

- [ ] **Step 2: Make successful login status idempotent**

Record the first successful login status on `Conn`; ignore subsequent successes without changing expected packet IDs or sending another `ClientCacheStatus`.

- [ ] **Step 3: Verify GREEN**

Run `go test ./minecraft -run TestDialContextIgnoresDuplicateLoginSuccess -count=1` and expect PASS.

### Task 3: Live Zeqa validation and publication

**Files:**
- No repository files unless live evidence identifies an additional gophertunnel defect.

**Interfaces:**
- Consumes: `*minecraft.TransferError` through `errors.As`.
- Produces: evidence that an authenticated bot follows Zeqa transfers and completes dial/spawn, or a concrete next defect with a regression test.

- [ ] **Step 1: Run a bounded authenticated transfer-follow harness**

Reuse the Lunar development token source and gophertunnel replacement, retrying the returned `Address:Port` for at most eight hops.

- [ ] **Step 2: Diagnose any next failure before editing**

Record the exact packet/error and add a minimal failing regression test for any library-owned defect.

- [ ] **Step 3: Verify and publish**

Run `go test ./...`, inspect the complete diff, commit only intended files, push `zeqa-patch`, and open a ready-for-review PR targeting `lunar`.

- [ ] **Step 4: Babysit the PR**

Poll checks and thread-aware bot reviews, fix real findings with regression coverage, rebut false positives, and continue until checks pass with no unresolved actionable threads.
