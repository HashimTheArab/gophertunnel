# Protocol drift

Compares every packet's `Marshal` implementation against schemas extracted from
a **running Bedrock Dedicated Server**, and fails when one drifts in a way that
has not been reviewed.

## Why this and not a round-trip test

A round-trip test encodes the same assumption the code does. If a field is
written and read with the same wrong encoding, the test passes forever.
`HurtArmour.ArmourSlots` zigzag-encoded a bitset with perfectly symmetric
marshalling — no round-trip test could have caught it.

This check compares against an *independent* description of the wire, so a
shared mistake in marshal and unmarshal still shows up.

It is also cheap to be wrong in the other direction: the 1.26.40 work shipped
two encoding bugs (`PlayerPermissions` written as a signed varint,
`EducationEditionOffer` as a zigzag) that were caught by review rather than by
tooling. Both would have failed this check before merge.

## The oracle

[endstonemc/protocol-docs](https://github.com/endstonemc/protocol-docs), produced
by `protocol-dumper` reading a live BDS. That is a stronger claim than published
documentation: it describes what the server actually serialises rather than what
a document asserts. Each release branch (`r26_u4`, …) is a dump of one build, so
the branch is the pin.

## How it works

1. `extract.go` walks every `Marshal` method with `go/ast`, recursing through
   helper types, and writes each packet's flattened wire operations. It needs no
   type-checking and downloads nothing.
2. `compare.mjs` flattens the BDS schemas the same way and diffs them per packet.

Each packet lands in one of four buckets: `AGREEMENT`, `DRIFT`, `UNRESOLVED`, or
`NO_GOPHERTUNNEL_PACKET`.

**`UNRESOLVED` never means agreement.** Where a `Marshal` hides bytes behind an
interface method the walker cannot follow (`ItemInstance`, `EntityMetadata`,
`ItemDescriptorCount`), or branches on a value at runtime, there is no single
linear byte sequence to compare and the packet is reported rather than assumed
correct. About 50 packets sit here today; that is coverage debt, not a pass.

## What it normalises, and what it refuses to

Equivalent, so collapsed:

- signed and unsigned fixed-width integers of the same width and endianness;
- a length-prefixed string and a length-prefixed byte slice — the encoding does
  not transform the payload;
- `UUID` against 16 raw bytes (position and length only — byte **order** inside
  the UUID is not verified);
- NBT compounds the server hands over pre-encoded, which are written verbatim
  with `io.Bytes`.

Deliberately kept distinct, because each difference is a wire bug:

- width, endianness, fixed-vs-varint, **varint-vs-zigzag**, option presence,
  array prefix type, fixed-array length, and union discriminants.

## Running it locally

```sh
git clone --depth 1 --branch r26_u4 https://github.com/endstonemc/protocol-docs schema-oracle
go run ./tools/protocoldrift .
node tools/protocoldrift/compare.mjs schema-oracle tools/protocoldrift/gophertunnel-flat.json
```

## When it fails

A new drift means one of three things, in rough order of likelihood:

1. **The packet is wrong.** Fix the encoding.
2. **The dump is wrong.** It is extracted from a binary and is not infallible —
   confirm against a capture, then add an entry to `accepted-drift.json` saying
   so.
3. **This comparison is too coarse.** Fix the comparator rather than the packet,
   and say so in the entry.

Every entry in `accepted-drift.json` carries a reason and what would settle it,
so "known drift" cannot quietly become "any drift". Nine packets are accepted
today: two where gophertunnel is very likely right, one being fixed, one
comparator limitation, and five genuinely unsettled and wanting a capture.
