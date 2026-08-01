# 04 — Let an External Subject submit a Meeting Proposal for exact Owner Approval

**What to build:** An External Subject can submit a Meeting Proposal but cannot create a calendar event. The Owner reviews the exact normalized operation in Telegram, and the gateway creates the event only after consuming a valid, short-lived Approval from the Approval Authority.

**Blocked by:** 03 — Give an External Subject a minimal Free/Busy View through Telegram.

**Status:** ready-for-agent

- [ ] A Meeting Proposal records the proposed interval, requester identity, reason and contact without creating an event.
- [ ] The Owner sees the exact Tool and normalized arguments before approving or denying.
- [ ] Approval binds Subject, Actor, Tool, arguments, trace, expiry and a one-time nonce.
- [ ] Replayed, expired or argument-mismatched approvals are denied before calendar execution.
- [ ] Retried approved requests create at most one event.
- [ ] External Subjects are rate-limited for availability queries and Meeting Proposals.
