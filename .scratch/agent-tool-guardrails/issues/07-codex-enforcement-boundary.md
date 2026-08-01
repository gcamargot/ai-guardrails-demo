# 07 — Connect Codex to the same Enforcement Boundary

**What to build:** Codex connects to the gateway over Streamable HTTP, authenticates through OAuth and uses one allowed development Tool. Codex client approvals provide a local defense, while the gateway independently prevents access to the smart lock.

**Blocked by:** 06 — Unlock the simulated smart lock only from the authorized Telegram turn.

**Status:** ready-for-agent

- [ ] Codex authenticates as the coding Actor for the Owner and successfully uses a narrow development Tool.
- [ ] Codex marks the gateway required and applies a local Tool allowlist and approval mode.
- [ ] The coding Actor does not discover the smart-lock Tool.
- [ ] A crafted MCP call that bypasses local discovery and approvals is still denied by OPA.
- [ ] Audit evidence clearly distinguishes the Owner Subject from the coding Actor.
- [ ] The demo explains that client controls may narrow but cannot broaden server authority.
