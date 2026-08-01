# 04 — Let an External Subject submit a Meeting Proposal for exact Owner Approval

**What to build:** An External Subject can submit a Meeting Proposal but cannot create a calendar event. The Owner reviews the exact normalized operation in Telegram, and the gateway creates the event only after consuming a valid, short-lived Approval from the Approval Authority.

**Blocked by:** 03 — Give an External Subject a minimal Free/Busy View through Telegram.

**Status:** ready-for-human

- [x] A Meeting Proposal records the proposed interval, requester identity, reason and contact without creating an event.
- [x] The Owner sees the exact Tool and normalized arguments before approving or denying.
- [x] Approval binds Subject, Actor, Tool, arguments, trace, expiry and a one-time nonce.
- [x] Replayed, expired or argument-mismatched approvals are denied before calendar execution.
- [x] Retried approved requests create at most one event.
- [x] External Subjects are rate-limited for availability queries and Meeting Proposals.

## Comments

- Implemented a local single-instance Meeting Proposal store, exact HMAC Approval Authority, OPA-enforced MCP Tools, per-Subject rate limits and an idempotent isolated calendar Effect. Redis remains the documented distributed-state evolution.
