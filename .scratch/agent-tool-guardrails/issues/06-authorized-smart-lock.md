# 06 — Unlock the simulated smart lock only from the authorized Telegram turn

**What to build:** The Owner can unlock the simulated demo lock only when the authenticated Subject, Telegram Actor, Telegram Channel, explicit Turn Capability, fixed device and exact Approval all match. Every other path is denied at the gateway.

**Blocked by:** 04 — Let an External Subject submit a Meeting Proposal for exact Owner Approval.

**Status:** ready-for-agent

- [ ] An Owner request with every required condition and a valid Approval unlocks the simulated device once.
- [ ] External Subjects and Unknown Subjects cannot discover or call the smart-lock Tool.
- [ ] A non-Telegram Actor is denied even when acting for the Owner.
- [ ] Missing capabilities, changed arguments, expired approvals and replayed approvals are denied.
- [ ] The adapter accepts only the fixed demo device and independently verifies its semantic invariants.
- [ ] Every allow and deny produces a correlated, non-sensitive audit record.
