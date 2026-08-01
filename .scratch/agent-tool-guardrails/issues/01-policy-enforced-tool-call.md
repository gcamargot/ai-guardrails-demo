# 01 — Execute one policy-enforced Tool Call end to end

**What to build:** A client can invoke one narrow Tool through the Go MCP gateway and receive a result from a simulated Protected Resource. The gateway validates the request and response, asks OPA for a Policy Decision, and exposes enough structured evidence to distinguish an allowed call from a denied call while running as a self-contained Docker Compose demo.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] A valid Tool Call traverses MCP, schema validation, OPA and the simulated adapter and returns a schema-valid result.
- [ ] An invalid or unauthorized Tool Call is denied before the adapter runs.
- [ ] Unknown input fields and output fields outside the Tool contract are rejected.
- [ ] Automated tests cover one allow, one deny and one schema failure.
- [ ] The complete slice starts reproducibly and reports component health.
