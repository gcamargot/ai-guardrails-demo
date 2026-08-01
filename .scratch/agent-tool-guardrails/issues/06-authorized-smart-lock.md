# 06 — Unlock the simulated smart lock only from the authorized Telegram turn

**What to build:** The Owner can unlock the simulated demo lock only when the authenticated Subject, Telegram Actor, Telegram Channel, explicit Turn Capability, fixed device and exact Approval all match. Every other path is denied at the gateway.

**Blocked by:** 04 — Let an External Subject submit a Meeting Proposal for exact Owner Approval.

**Status:** ready-for-human

- [x] An Owner request with every required condition and a valid Approval unlocks the simulated device once.
- [x] External Subjects and Unknown Subjects cannot discover or call the smart-lock Tool.
- [x] A non-Telegram Actor is denied even when acting for the Owner.
- [x] Missing capabilities, changed arguments, expired approvals and replayed approvals are denied.
- [x] The adapter accepts only the fixed demo device and independently verifies its semantic invariants.
- [x] Every allow and deny produces a correlated, non-sensitive audit record.

## Comments

- Implemented explicit Telegram review/unlock commands, exact short-lived single-use Approval, OPA discovery/execution filtering, an isolated Vault-authenticated simulated adapter and a typed non-sensitive audit collector. The Compose smoke covers the complete allow/deny matrix and verifies exactly one Effect.
