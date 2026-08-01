# 09 — Observe decisions and prove fail-closed operation

**What to build:** An operator can follow a Tool Call from authenticated request through Policy Decision to Effect using correlated telemetry, without exposing sensitive content. A reproducible verification suite demonstrates that unavailable or malformed control-plane dependencies fail closed.

**Blocked by:** 08 — Deliver policies as tested, signed artifacts.

**Status:** ready-for-agent

- [ ] Gateway spans, OPA decisions and adapter results share trace and decision identifiers.
- [ ] Logs include identities, Tool, safe normalized arguments, rule, revision, obligations, outcome and timing.
- [ ] Log masking removes tokens, secrets, email bodies, full prompts and sensitive event data.
- [ ] OPA, identity or Approval Authority unavailability denies every Tool Call, including Free/Busy reads.
- [ ] Malformed inputs and outputs are denied with an auditable reason.
- [ ] Network checks prove that Telegram, Qwen and Codex cannot reach isolated adapters directly.
