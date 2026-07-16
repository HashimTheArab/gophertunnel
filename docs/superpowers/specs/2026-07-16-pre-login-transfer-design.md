# Pre-login Transfer Handling Design

## Goal

Return structured transfer details when a Bedrock server sends `Transfer` before the client dial sequence completes, so callers can reconnect without waiting for a timeout.

## Ownership

The behavior belongs in `minecraft.Conn` because that layer decodes packets and owns the pre-login state machine. Callers must not parse error strings or raw packet bytes.

## Behavior

- When `Transfer` arrives before `Conn.loggedIn`, decode it immediately.
- End the dial with a `*minecraft.TransferError` containing `Address`, `Port`, and `ReloadWorld`.
- Preserve the existing `*net.OpError` dial wrapper so normal network error inspection continues to work.
- Treat repeated `PlayStatusLoginSuccess` packets as idempotent so they cannot rewind a connection from world initialization back to resource-pack negotiation.
- Leave ordinary login behavior unchanged.
- Do not make gophertunnel automatically reconnect: callers own redirect policy, hop limits, authentication reuse, and cancellation.

## Verification

An in-memory scripted Bedrock server will send a pre-login `Transfer` and assert that dial returns the typed details and closes the abandoned connection. Additional tests complete an ordinary login and a login containing a duplicate success status. Live validation uses Zeqa and a bounded caller-side transfer loop.
