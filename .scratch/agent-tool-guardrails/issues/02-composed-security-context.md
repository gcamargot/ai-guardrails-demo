# 02 — Authenticate a composed Security Context

**What to build:** A caller authenticates through Keycloak and the gateway derives a trusted Security Context containing Subject, Actor and Channel. Model Interpretation remains separate data and cannot assert identity or enlarge authority.

**Blocked by:** 01 — Execute one policy-enforced Tool Call end to end.

**Status:** ready-for-human

- [x] The gateway verifies issuer, audience, signature, expiry and required claims before evaluating policy.
- [x] Two OAuth clients produce distinguishable Actors while preserving the authenticated Subject.
- [x] Missing, expired, malformed and incorrectly scoped tokens fail closed before adapter execution.
- [x] Changing a model-produced user, actor or capability field does not change the effective Security Context.
- [x] Tests demonstrate that the effective identity comes only from trusted claims and channel binding.

## Comments

- Implemented with a per-request OIDC Security Context, Keycloak Compose fixture, OPA policy revision `ticket-02`, public seam tests and a black-box smoke covering both OAuth clients.
