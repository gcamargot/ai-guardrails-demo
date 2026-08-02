# 09 — Observe decisions and prove fail-closed operation

**What to build:** An operator can follow a Tool Call from authenticated request through Policy Decision to Effect using correlated telemetry, without exposing sensitive content. A reproducible verification suite demonstrates that unavailable or malformed control-plane dependencies fail closed.

**Blocked by:** 08 — Deliver policies as tested, signed artifacts.

**Status:** ready-for-human

- [x] Gateway spans, OPA decisions and adapter results share trace and decision identifiers.
- [x] Logs include identities, Tool, safe normalized arguments, rule, revision, obligations, outcome and timing.
- [x] Log masking removes tokens, secrets, email bodies, full prompts and sensitive event data.
- [x] OPA, identity or Approval Authority unavailability denies every Tool Call, including Free/Busy reads.
- [x] Malformed inputs and outputs are denied with an auditable reason.
- [x] Network checks prove that Telegram, Qwen and Codex cannot reach isolated adapters directly.

## Comments

Implemented with correlated structured audit, signed OPA log masking, control-plane health gates, malformed-I/O evidence and Compose failure/network probes. Ready for human review after the full Go, Rego, policy CI and Docker smoke suites passed.
