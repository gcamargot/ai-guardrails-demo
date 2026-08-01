# 03 — Give an External Subject a minimal Free/Busy View through Telegram

**What to build:** An External Subject can ask for availability through Telegram, have the request interpreted by local Qwen, and receive only a bounded Free/Busy View from an isolated demo calendar. The Telegram identity is mapped into the trusted Security Context independently of the model.

**Blocked by:** 02 — Authenticate a composed Security Context.

**Status:** ready-for-human

- [x] A verified Telegram identity maps to an External Subject and Telegram Actor without trusting classifier output.
- [x] The External Subject discovers the availability Tool but no Tool that reveals calendar event contents.
- [x] Availability is limited to the configured future window and working hours.
- [x] The response exposes available intervals but no titles, descriptions, attendees or occupied-event details.
- [x] Calendar credentials come from Vault and never enter the prompt, response or audit log.
- [x] Automated tests cover allowed availability, out-of-window requests and response minimization.

## Comments

- Implemented with a verified synthetic Telegram webhook, deterministic Qwen classifier, External Subject OIDC mapping, capability-filtered MCP discovery, bounded Rego policy, strict Free/Busy response controls, Vault-backed calendar credential and black-box Compose smoke.
