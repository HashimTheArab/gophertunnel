# gophertunnel (lunar fork)

Maintained fork of `sandertv/gophertunnel` (working branch `lunar`). The module path stays
upstream; consumers point at this fork with a `replace` directive.

## Semantic marshal operations are mandatory

Actor IDs and player input ticks must never be marshalled through raw integer primitives.
When adding or changing a packet or protocol struct field:

| Field carries | Use |
|---|---|
| Actor runtime ID (varuint64) | `io.ActorRuntimeID` |
| Actor unique ID (varint64) | `io.ActorUniqueID` |
| Actor ID in a legacy encoding | `protocol.ActorRuntimeIDInt64` / `ActorRuntimeIDUint32` / `ActorUniqueIDFixed` / `ActorUniqueIDUint64` / `ActorUniqueIDVaruint64` |
| Tick on the player input timeline (the serverbound input tick and the clientbound echoes rewind is keyed on) | `io.PlayerInputTick` |

These operations are what `packet.TranslateEntityIDs`, `packet.TranslateInputTicks` and
the connection-level ID translation rewrite. A field marshalled with `io.Varuint64`
instead is invisible to all of them and silently breaks proxies that swap upstream
sessions — the exact bug class the semantic ops exist to prevent.

Related: entity metadata keys whose values are actor unique IDs must be added to
`entityMetadataActorIDKeys` in `minecraft/protocol/translate_io.go` (applied through
`protocol.TranslateEntityMetadataIDs`) — there is no naming pattern a discovery test can
match, so this manual list is the only gate. New IO implementations must forward
`SliceLength` (see `sliceReader`) or slice decoding breaks behind them.

## The coverage tests are the enforcement — keep them strict

`minecraft/protocol/packet/translate_test.go` and `translate_manifest_test.go` discover
ID- and tick-like field names by pattern and fail when one is not covered:

- New matching field → add it to `translatedIDFields` / `translatedTickFields` **and**
  mark it with the semantic op. Add a fixture only if the reflective setter cannot reach
  the field (flag-gated, optional, enum-guarded).
- Field that matches but is deliberately untranslated → list it in the ignored set with
  a reason. Never widen or weaken the discovery patterns to make a failure go away.
- IDs behind interface fields or metadata values are not discoverable; cover them by hand
  in the manifest or interface tests when adding any.

Wire goldens in `translate_wire_test.go` pin encodings across such migrations; generate
new goldens with the encoder from **before** the change.
