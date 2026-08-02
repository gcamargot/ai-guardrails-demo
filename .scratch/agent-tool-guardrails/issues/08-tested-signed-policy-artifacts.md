# 08 — Deliver policies as tested, signed artifacts

**What to build:** The complete authorization matrix is represented as versioned Rego policies with executable positive and negative examples. OPA loads only verified bundles and exposes the active policy revision with each relevant decision.

**Blocked by:** 04 — Let an External Subject submit a Meeting Proposal for exact Owner Approval; 05 — Let the Owner read Outlook without acting on Untrusted Content; 06 — Unlock the simulated smart lock only from the authorized Telegram turn; 07 — Connect Codex to the same Enforcement Boundary.

**Status:** ready-for-human

- [x] Policy tests cover every Subject and Actor combination in the agreed authorization matrix.
- [x] Tests cover discovery filtering, execution authorization, Turn Capabilities, argument constraints and obligations.
- [x] The policy workflow rejects formatting, compilation and unit-test failures before publishing a bundle.
- [x] OPA verifies the bundle signature and retains the prior valid revision when an update is invalid.
- [x] Decisions expose a correlation identifier and active policy revision.
- [x] The documented ownership workflow requires Platform/Security and the relevant resource owner for sensitive changes.
