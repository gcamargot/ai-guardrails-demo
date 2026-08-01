# Agent Tool Guardrails

Tracer-bullet implementation of a mandatory MCP Enforcement Boundary. A client authenticates with Keycloak and calls the narrow `coffee_station.get_status` Tool; the Go gateway validates the signed identity, composes a Security Context, obtains an OPA Policy Decision, calls an isolated simulated Protected Resource, validates the response, and returns structured MCP content with the OPA `decision_id` and policy revision.

## Run

```sh
./scripts/smoke.sh
```

The smoke path proves these outcomes:

- A request without a Bearer token fails with `401` before OPA or the Protected Resource.
- Keycloak issues signed tokens for `telegram-agent` and `coding-agent` with the same authenticated Subject and distinct Actors.
- Both Actors may read `demo-station` and receive `state: ready` through policy revision `ticket-02`.
- A forged Model Interpretation claiming another user, Actor or sensitive capability cannot alter the effective Security Context.

The gateway is available at `http://localhost:8080/mcp`; readiness for both OPA and the Protected Resource is available at `http://localhost:8080/healthz`. Keycloak is imported from [`keycloak/agent-tools-realm.json`](keycloak/agent-tools-realm.json) and is only used inside the isolated Compose demo path.

## Security Context composition

The gateway accepts identity only from the Bearer token after OIDC discovery and verification of its signature, issuer, audience and expiry. It maps `sub` to Subject, `azp` to Actor, intersects the signed `scope` claim with configured Turn Capabilities, and adds the deployment-bound Channel. Missing claims or scopes fail closed.

Model Interpretation may travel in MCP `_meta`, but that data is not copied into the Security Context or OPA input. Keycloak uses demo-only direct access grants and checked-in credentials so the scenario is reproducible; they are not production defaults or secrets.

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

The demo pins Keycloak `26.7.0`, OPA `1.17.0` and Go `1.25.7`. The smoke teardown removes all containers and networks after either success or failure.
