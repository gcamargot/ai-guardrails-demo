# 05 — Let the Owner read Outlook without acting on Untrusted Content

**What to build:** The Owner explicitly grants a read-only Turn Capability through Telegram, reads a specifically requested demo email, and receives a minimized result. Instructions embedded in the email remain Untrusted Content and cannot become Subject intent or trigger another Effect.

**Blocked by:** 04 — Let an External Subject submit a Meeting Proposal for exact Owner Approval.

**Status:** ready-for-human

- [x] Only the Owner using the Telegram Actor can discover and call Outlook read Tools.
- [x] A button or deterministic command grants a short-lived, read-only Turn Capability for the interaction.
- [x] Search and read operations are scoped to the requested query or message rather than unrestricted mailbox access.
- [x] A prepared email containing prompt injection can be summarized but cannot invoke a calendar, meeting or smart-home Tool.
- [x] A new explicit user interaction is required before any later Effect can be authorized.
- [x] Email bodies, secrets and full prompts do not appear in decision or application logs.

## Comments

- Implemented deterministic Owner-only Telegram commands, optional per-interaction OIDC scope, two narrow MCP Tools, OPA enforcement, a GET-only isolated Outlook fixture, response minimization and smoke assertions for zero additional Effects and log hygiene.
