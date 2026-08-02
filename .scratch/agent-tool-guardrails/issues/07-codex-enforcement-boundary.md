# 07 — Connect Codex to the same Enforcement Boundary

**What to build:** Codex connects to the gateway over Streamable HTTP, authenticates through OAuth and uses one allowed development Tool. Codex client approvals provide a local defense, while the gateway independently prevents access to the smart lock.

**Blocked by:** 06 — Unlock the simulated smart lock only from the authorized Telegram turn.

**Status:** ready-for-human

- [x] Codex authenticates as the coding Actor for the Owner and successfully uses a narrow development Tool.
- [x] Codex marks the gateway required and applies a local Tool allowlist and approval mode.
- [x] The coding Actor does not discover the smart-lock Tool.
- [x] A crafted MCP call that bypasses local discovery and approvals is still denied by OPA.
- [x] Audit evidence clearly distinguishes the Owner Subject from the coding Actor.
- [x] The demo explains that client controls may narrow but cannot broaden server authority.

## Comments

- Implemented a Codex Streamable HTTP OAuth configuration, RFC 9728 discovery, Keycloak Authorization Code + PKCE for Actor `coding-agent`, the exact `dev.read_repository` Tool over an isolated adapter, ticket-07 Rego policy, and black-box evidence that client controls narrow but never broaden gateway authority.
