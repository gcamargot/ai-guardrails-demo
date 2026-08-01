# Agent Tool Guardrails

Tracer-bullet implementation of a mandatory MCP Enforcement Boundary. Authenticated clients can call narrow Tools for the demo coffee station, calendar and read-only Outlook resources. The Go gateway validates signed identity, composes a Security Context, obtains an OPA Policy Decision, calls network-isolated simulated Protected Resources, validates and minimizes their responses, and returns structured MCP content with the OPA `decision_id` and policy revision.

## Run

```sh
./scripts/smoke.sh
```

The smoke path proves these outcomes:

- A request without a Bearer token fails with `401` before OPA or the Protected Resource.
- Keycloak issues signed tokens for `telegram-agent` and `coding-agent` with the same authenticated Subject and distinct Actors.
- Both Actors may read `demo-station` and receive `state: ready` through policy revision `ticket-05`.
- A forged Model Interpretation claiming another user, Actor or sensitive capability cannot alter the effective Security Context.
- A verified Telegram update maps user `4242` to `external-alice-subject-id`; the deterministic Qwen simulator may classify only the requested time window and cannot assert authority.
- That External Subject discovers only `calendar.find_availability` and `calendar.submit_meeting_proposal`; availability reveals only bounded `start`/`end` intervals.
- Availability and Meeting Proposals have independent per-Subject rate limits. A proposal records interval, requester, reason and contact without calling the calendar.
- Telegram user `9001` maps to the Owner. `/review proposal-1` returns the exact normalized `calendar.create_event` operation and a short-lived review token; only `/approve proposal-1 <token>` or `/deny proposal-1 <token>` can resolve it.
- The isolated Approval Authority signs a two-minute Approval bound to Owner Subject, Telegram Actor, Tool, canonical arguments, trace, expiry and a random nonce. The gateway consumes it atomically before the calendar Effect; mismatch, expiry, replay or Authority failure deny closed.
- Calendar creation uses `meeting-proposal:<id>` as an idempotency key, so retries return the same synthetic event and keep `event_count=1`.
- The Owner's deterministic `/outlook-search <query>` and `/outlook-read <message-id>` commands request the optional `outlook.mail.read` Turn Capability for one short interaction. Without it, Outlook Tools are not discoverable.
- The prepared email contains a prompt-injection sentinel. Its minimized view is explicitly marked `untrusted_content`, contains no body, and keeps `outlook_effect_count=0`; a later Effect still requires a new explicit command and capability.
- Gateway, calendar and Outlook load synthetic downstream credentials from Vault. The smoke fails if credentials, email bodies or full prompt sentinels appear in service logs.

The gateway is available at `http://localhost:8080/mcp`, and the synthetic Telegram webhook at `http://localhost:8084/telegram/webhook`. Keycloak is imported from [`keycloak/agent-tools-realm.json`](keycloak/agent-tools-realm.json). Vault runs in dev mode, and all checked-in identities and credentials are synthetic fixtures for the isolated demo only.

## Security Context composition

The gateway accepts identity only from the Bearer token after OIDC discovery and verification of its signature, issuer, audience and expiry. It maps `sub` to Subject, `azp` to Actor, intersects the signed `scope` claim with configured Turn Capabilities, and adds the deployment-bound Channel. Missing claims or scopes fail closed.

Model Interpretation may travel in MCP `_meta`, but that data is not copied into the Security Context or OPA input. Keycloak uses demo-only direct access grants and checked-in credentials so the scenario is reproducible; they are not production defaults or secrets.

The Telegram ingress verifies its webhook secret before mapping the Telegram user ID. It obtains an OIDC token for the mapped External Subject and calls a gateway deployment bound to Channel `telegram`. The separate Qwen service returns a deterministic JSON interpretation containing only the time range used by the adapter; extra identity or capability fields are ignored. Qwen, Telegram ingress and smoke clients share no network with the calendar adapter.

## Free/Busy controls

OPA allows the External Subject to discover only `calendar.find_availability`. Execution is constrained to weekdays, 09:00–17:00 UTC, and a 14-day future horizon. The calendar HTTP client rejects unknown response fields, while the MCP boundary independently validates that every returned interval is ordered and contained within the authorized request. Titles, descriptions, attendees and occupied-event details are not part of any response type.

Vault is the source of the calendar credential for both sides of the isolated connection. The demo initializer creates separate, read-only Vault policies and ephemeral tokens for the gateway and calendar; token files live in a temporary Compose volume removed by smoke teardown. The calendar credential is placed only in an authorization header between the gateway and calendar and is never sent to Qwen, MCP output or OPA decision input.

## Exact Meeting Proposal approval

An External Subject uses `/propose <start> <end> <contact> <reason>` to create only local pending state. The Owner uses `/review <proposal-id>` before an explicit `/approve <proposal-id> <review-token>` or `/deny <proposal-id> <review-token>`. Review explicitly requests the optional `calendar.meeting.approve` Turn Capability, displays the exact normalized operation and asks the dedicated Approval Authority to attest it. The sensitive capability is not a default Keycloak scope. Resolution passes the opaque Approval to the gateway; direct resolution without the reviewed token is rejected. The Approval Authority has neither a calendar credential nor network access to Protected Resources.

Consumed Approval nonces are fsync'd to a local Compose volume and reloaded after Approval Authority restarts. Proposal resolution is atomic in the single gateway process, while rate-limit counters and calendar idempotency records remain local. Redis with atomic scripts and replicated state is the documented production evolution. Checked-in Approval credentials and signing material are synthetic Compose fixtures, never model inputs or production secrets.

## Read-only Outlook controls

Only the Owner through the Telegram Actor and Channel can discover or execute `outlook.search_messages` and `outlook.read_message`. The optional Keycloak scope is requested only while handling an explicit command; it is neither a default scope nor persistent interaction state. Search accepts an exact query of at most 100 characters and returns at most five metadata-only matches. Read accepts one strict demo message ID.

The Outlook service exposes only authenticated GET routes on the isolated network. It stores a prepared email body containing hostile instructions, but returns only `message_id`, sender, subject, timestamp and a bounded summary labelled `untrusted_content`. The body never reaches OPA, Telegram output or a model prompt. A separate internal observability network exposes only the synthetic calendar Effect count to the test-profile smoke client, proving the email read adds zero Effects without giving that client calendar or Outlook credentials.

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
```

The demo pins Keycloak `26.7.0`, OPA `1.17.0`, Vault `1.21.4` and Go `1.25.7`. The smoke teardown removes all containers and networks after either success or failure.
