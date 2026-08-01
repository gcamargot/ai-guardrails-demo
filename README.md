# Agent Tool Guardrails

Tracer-bullet implementation of a mandatory MCP Enforcement Boundary. Authenticated clients can call narrow Tools for the demo coffee station and a minimized calendar Free/Busy View. The Go gateway validates signed identity, composes a Security Context, obtains an OPA Policy Decision, calls network-isolated simulated Protected Resources, validates their responses, and returns structured MCP content with the OPA `decision_id` and policy revision.

## Run

```sh
./scripts/smoke.sh
```

The smoke path proves these outcomes:

- A request without a Bearer token fails with `401` before OPA or the Protected Resource.
- Keycloak issues signed tokens for `telegram-agent` and `coding-agent` with the same authenticated Subject and distinct Actors.
- Both Actors may read `demo-station` and receive `state: ready` through policy revision `ticket-03`.
- A forged Model Interpretation claiming another user, Actor or sensitive capability cannot alter the effective Security Context.
- A verified Telegram update maps user `4242` to `external-alice-subject-id`; the deterministic Qwen simulator may classify only the requested time window and cannot assert authority.
- That External Subject discovers only `calendar.find_availability`, receives only available `start`/`end` intervals during the next 14 days and UTC working hours, and is denied outside the horizon before calendar access.
- Both gateway and isolated calendar load their shared synthetic calendar credential from Vault. The smoke fails if that credential appears in service logs.

The gateway is available at `http://localhost:8080/mcp`, and the synthetic Telegram webhook at `http://localhost:8084/telegram/webhook`. Keycloak is imported from [`keycloak/agent-tools-realm.json`](keycloak/agent-tools-realm.json). Vault runs in dev mode, and all checked-in identities and credentials are synthetic fixtures for the isolated demo only.

## Security Context composition

The gateway accepts identity only from the Bearer token after OIDC discovery and verification of its signature, issuer, audience and expiry. It maps `sub` to Subject, `azp` to Actor, intersects the signed `scope` claim with configured Turn Capabilities, and adds the deployment-bound Channel. Missing claims or scopes fail closed.

Model Interpretation may travel in MCP `_meta`, but that data is not copied into the Security Context or OPA input. Keycloak uses demo-only direct access grants and checked-in credentials so the scenario is reproducible; they are not production defaults or secrets.

The Telegram ingress verifies its webhook secret before mapping the Telegram user ID. It obtains an OIDC token for the mapped External Subject and calls a gateway deployment bound to Channel `telegram`. The separate Qwen service returns a deterministic JSON interpretation containing only the time range used by the adapter; extra identity or capability fields are ignored. Qwen, Telegram ingress and smoke clients share no network with the calendar adapter.

## Free/Busy controls

OPA allows the External Subject to discover only `calendar.find_availability`. Execution is constrained to weekdays, 09:00–17:00 UTC, and a 14-day future horizon. The calendar HTTP client rejects unknown response fields, while the MCP boundary independently validates that every returned interval is ordered and contained within the authorized request. Titles, descriptions, attendees and occupied-event details are not part of any response type.

Vault is the source of the calendar credential for both sides of the isolated connection. The demo initializer creates separate, read-only Vault policies and ephemeral tokens for the gateway and calendar; token files live in a temporary Compose volume removed by smoke teardown. The calendar credential is placed only in an authorization header between the gateway and calendar and is never sent to Qwen, MCP output or OPA decision input.

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
