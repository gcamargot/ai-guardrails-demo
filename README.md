# Agent Tool Guardrails

Tracer-bullet implementation of a mandatory MCP Enforcement Boundary. Authenticated clients can call narrow Tools for the demo coffee station, calendar and read-only Outlook resources. The Go gateway validates signed identity, composes a Security Context, obtains an OPA Policy Decision, calls network-isolated simulated Protected Resources, validates and minimizes their responses, and returns structured MCP content with the correlation identifier, OPA `decision_id`, obligations and active policy revision.

## Run

```sh
./scripts/smoke.sh
```

The smoke path proves these outcomes:

- A request without a Bearer token fails with `401` before OPA or the Protected Resource.
- Keycloak issues signed tokens for `telegram-agent` and `coding-agent` with the same authenticated Subject and distinct Actors.
- Both Actors may read `demo-station` and receive `state: ready` through policy revision `ticket-09`.
- The Owner's coding Actor can use the exact `dev.read_repository` Tool for allowlisted `CONTEXT.md`; the isolated adapter rejects other paths.
- The coding Actor does not discover `smart_lock.unlock`. A crafted raw MCP call that bypasses Codex's allowlist and approval prompt is still denied by OPA, produces no Effect, and emits audit evidence separating Owner Subject from `coding-agent` Actor.
- A forged Model Interpretation claiming another user, Actor or sensitive capability cannot alter the effective Security Context.
- A verified Telegram update maps user `4242` to `external-alice-subject-id`; the deterministic Qwen simulator may classify only the requested time window and cannot assert authority.
- That External Subject discovers only `calendar.find_availability` and `calendar.submit_meeting_proposal`; availability reveals only bounded `start`/`end` intervals.
- Availability and Meeting Proposals have independent per-Subject rate limits. A proposal records interval, requester, reason and contact without calling the calendar.
- Telegram user `9001` maps to the Owner. `/review proposal-1` returns the exact normalized `calendar.create_event` operation and a short-lived review token; only `/approve proposal-1 <token>` or `/deny proposal-1 <token>` can resolve it.
- The isolated Approval Authority signs a short-lived Approval bound to Owner Subject, Telegram Actor, Tool, canonical arguments, trace, expiry and a random nonce. Its default TTL is two minutes and the Compose smoke uses five seconds to demonstrate expiry. The gateway consumes it atomically before an Effect; mismatch, expiry, replay or Authority failure deny closed.
- Calendar creation uses `meeting-proposal:<id>` as an idempotency key, so retries return the same synthetic event and keep `event_count=1`.
- The Owner's deterministic `/outlook-search <query>` and `/outlook-read <message-id>` commands request the optional `outlook.mail.read` Turn Capability for one short interaction. Without it, Outlook Tools are not discoverable.
- The prepared email contains a prompt-injection sentinel. Its minimized view is explicitly marked `untrusted_content`, contains no body, and keeps `outlook_effect_count=0`; a later Effect still requires a new explicit command and capability.
- Gateway, calendar and Outlook load synthetic downstream credentials from Vault. The smoke fails if credentials, email bodies or full prompt sentinels appear in service logs.
- Every Tool Call emits structured operational evidence joining gateway trace, OPA correlation and decision identifiers, safe normalized arguments, rule, revision, obligations, outcome and timing. OPA decision logs remove sensitive argument paths before emission.
- The smoke deliberately makes identity, OPA and Approval Authority unavailable; even Free/Busy reads deny closed and the calendar Effect count remains unchanged. A malformed adapter response is also denied with an auditable reason.
- Test-profile probes with the exact network memberships of Telegram, Qwen and Codex prove that those clients cannot resolve or connect to Protected Resource adapters directly.

The gateway is available at `http://localhost:8080/mcp`, and the synthetic Telegram webhook at `http://localhost:8084/telegram/webhook`. Keycloak is imported from [`keycloak/agent-tools-realm.json`](keycloak/agent-tools-realm.json). Vault runs in dev mode, and all checked-in identities and credentials are synthetic fixtures for the isolated demo only.

## Security Context composition

The gateway accepts identity only from the Bearer token after OIDC discovery and verification of its signature, issuer, audience and expiry. It maps `sub` to Subject, `azp` to Actor, intersects the signed `scope` claim with configured Turn Capabilities, and adds the deployment-bound Channel. Missing claims or scopes fail closed.

Model Interpretation may travel in MCP `_meta`, but that data is not copied into the Security Context or OPA input. Telegram and the automated smoke use demo-only direct access grants and checked-in credentials so the scenario is reproducible; the Codex client uses Authorization Code with PKCE. None are production credentials.

The Telegram ingress verifies its webhook secret before mapping the Telegram user ID. It obtains an OIDC token for the mapped External Subject and calls a gateway deployment bound to Channel `telegram`. The separate Qwen service returns a deterministic JSON interpretation containing only the time range used by the adapter; extra identity or capability fields are ignored. Qwen, Telegram ingress and smoke clients share no network with the calendar adapter.

## Free/Busy controls

OPA allows the External Subject to discover only `calendar.find_availability`. Execution is constrained to weekdays, 09:00–17:00 UTC, and a 14-day future horizon. The calendar HTTP client rejects unknown response fields, while the MCP boundary independently validates that every returned interval is ordered and contained within the authorized request. Titles, descriptions, attendees and occupied-event details are not part of any response type.

Vault is the source of the calendar credential for both sides of the isolated connection. The demo initializer creates separate, read-only Vault policies and ephemeral tokens for the gateway and calendar; token files live in a temporary Compose volume removed by smoke teardown. The calendar credential is placed only in an authorization header between the gateway and calendar and is never sent to Qwen, MCP output or OPA decision input.

## Exact Meeting Proposal approval

An External Subject uses `/propose <start> <end> <contact> <reason>` to create only local pending state. The Owner uses `/review <proposal-id>` before an explicit `/approve <proposal-id> <review-token>` or `/deny <proposal-id> <review-token>`. Review explicitly requests the optional `calendar.meeting.approve` Turn Capability, displays the exact normalized operation and asks the dedicated Approval Authority to attest it. The sensitive capability is not a default Keycloak scope. Resolution passes the opaque Approval to the gateway; direct resolution without the reviewed token is rejected. The Approval Authority has neither a calendar credential nor network access to Protected Resources.

Consumed Approval nonces are fsync'd to a local Compose volume and reloaded after Approval Authority restarts. Proposal resolution is atomic in the single gateway process, while rate-limit counters and calendar idempotency records remain local. Redis with atomic scripts and replicated state is the documented production evolution. Checked-in Approval credentials and signing material are synthetic Compose fixtures, never model inputs or production secrets.

## Authorized simulated Smart Lock

The Owner first sends `/review-unlock demo-front-door` through the authenticated Telegram adapter. That explicit command requests the optional `smart_lock.write` Turn Capability and returns the exact `smart_lock.unlock` operation plus a short-lived Approval. `/unlock demo-front-door <trace-id> <approval>` can produce the Effect only when Subject, Telegram Actor, Telegram Channel, Turn Capability, fixed device, reviewed trace and signed Approval all still match. External and Unknown Subjects, coding clients, missing capabilities, changed arguments, expired Approvals and replayed Approvals fail before the isolated adapter.

The adapter independently accepts only `demo-front-door`, validates the semantic `locked -> unlocked` transition and reads its synthetic downstream credential from Vault. The gateway writes typed audit records to an isolated collector before an authorized Effect. Records correlate `decision_id` and the Approval-bound trace where available, classify the Subject without storing its identifier, and have no field capable of carrying the Approval or downstream credentials.

## Read-only Outlook controls

Only the Owner through the Telegram Actor and Channel can discover or execute `outlook.search_messages` and `outlook.read_message`. The optional Keycloak scope is requested only while handling an explicit command; it is neither a default scope nor persistent interaction state. Search accepts an exact query of at most 100 characters and returns at most five metadata-only matches. Read accepts one strict demo message ID.

The Outlook service exposes only authenticated GET routes on the isolated network. It stores a prepared email body containing hostile instructions, but returns only `message_id`, sender, subject, timestamp and a bounded summary labelled `untrusted_content`. The body never reaches OPA, Telegram output or a model prompt. A separate internal observability network exposes only the synthetic calendar Effect count to the test-profile smoke client, proving the email read adds zero Effects without giving that client calendar or Outlook credentials.

## Codex as a second MCP client

[`examples/codex/config.toml`](examples/codex/config.toml) is the client-control fragment for the live demo. With a current Codex CLI, first register the static OAuth client through the supported command:

```sh
codex mcp add agent_tool_guardrails \
  --url http://127.0.0.1:8080/mcp \
  --oauth-client-id coding-agent
```

The gateway metadata already declares the OAuth resource, so the Codex configuration intentionally does not repeat `oauth_resource`. Then add the example's `auth`, `required`, `scopes`, `enabled_tools` and approval settings to the generated table, start the Compose gateway, and run this if the add command did not already complete login:

```sh
codex mcp login agent_tool_guardrails
```

The gateway's `401` challenge points Codex to RFC 9728 protected-resource metadata, which in turn identifies the demo Keycloak issuer. Keycloak authenticates the Owner and issues a PKCE-bound token whose `azp` establishes Actor `coding-agent`; the gateway validates its external issuer, audience, expiry, signature and `dev.repository.read` scope. The server is marked `required`, its client-visible allowlist contains only `dev.read_repository`, and every invocation prompts locally.

Codex CLI 0.146.0 currently drops the RFC 9207 `iss` callback parameter before its own validation. The small `oauth-facade` service proxies Keycloak unchanged except for advertising `authorization_response_iss_parameter_supported=false` in both OIDC and RFC 8414 metadata, the server-side workaround for [openai/codex#34684](https://github.com/openai/codex/issues/34684). Keycloak still performs Authorization Code + S256 PKCE and issues the token; the gateway still validates the real issuer and obtains signing keys directly over the isolated identity network.

Those settings are a useful client defense and UX control, not the Enforcement Boundary. Removing `dev.read_repository` from `enabled_tools` narrows what Codex can use. Adding `smart_lock.unlock` locally cannot broaden authority: server discovery still filters it and a crafted direct `tools/call` is independently denied by OPA before Approval Authority or Smart Lock access. Audit stores `subject_kind=owner` separately from `actor=coding-agent` without persisting the Subject identifier.

## Tested and signed Policy Artifacts

[`scripts/policy-ci.sh`](scripts/policy-ci.sh) is the single publishing path. It rejects unformatted Rego, strict compilation failures, an empty or failing unit-test suite, and an incomplete ownership contract before producing anything. Only after every gate succeeds does it build a revisioned ES256 bundle under `.artifacts/policy/`. [`scripts/policy-ci-test.sh`](scripts/policy-ci-test.sh) runs an executable fixture for each rejection mode plus the valid publishing path.

OPA no longer mounts policy source. It downloads the artifact from the internal Bundle Service, verifies its signature against the independently configured public key, and becomes ready only after the first bundle activates. Every Policy Decision echoes a gateway-generated `correlation_id`, its `decision_id`, obligations and the revision stored inside the active artifact. The smoke offers OPA an update signed by an untrusted key, observes the signature error through Status API, verifies that `active_revision` remains `ticket-09`, and successfully evaluates another Tool Call against that last good revision.

The EC private keys under `policies/keys/` are synthetic fixtures for this isolated demo and must never be reused. A production pipeline would keep the signing key in a KMS, HSM or Vault transit engine and distribute only its public key to OPA. [`policies/OWNERS.md`](policies/OWNERS.md) requires two independent approvals for sensitive policy changes: Platform/Security for the Enforcement Boundary and signing workflow, plus the relevant Protected Resource owner for intended authority and constraints.

## Observable fail-closed operation

The gateway creates a fresh `trace_id` at the MCP boundary and propagates it with `correlation_id` and `decision_id` to the selected adapter. The audit collector accepts only typed records and per-Tool allow-listed argument keys. It stores Subject classification rather than the Subject identifier and never accepts Bearer or Approval tokens, credentials, message bodies, full prompts, mailbox queries, contacts or meeting reasons. The signed bundle includes `system.log.mask`, which removes those sensitive paths from OPA decision logs as a separate defense.

Approval Authority health is a common execution prerequisite, including read-only Free/Busy. Identity health is checked against JWKS before cached token verification, and OPA errors remain hard denies. Unavailable dependencies and malformed input or adapter output produce correlated deny records before results cross the Enforcement Boundary. `scripts/smoke.sh` exercises all four failures, bounds recovery waits, verifies zero additional calendar Effects and tears down the isolated environment on success or failure.

## Test

Go is intentionally run in the pinned container used by the build:

```sh
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  golang:1.25.7-alpine \
  go test ./...

docker run --rm \
  -v "$PWD/policies:/policies:ro" \
  openpolicyagent/opa:1.17.0-static \
  test /policies

./scripts/policy-ci-test.sh
```

The demo pins Keycloak `26.7.0`, OPA `1.17.0`, Vault `1.21.4` and Go `1.25.7`. The smoke teardown removes all containers and networks after either success or failure.
