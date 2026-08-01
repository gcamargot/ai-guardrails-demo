# Agent Tool Guardrails

Tracer-bullet implementation of a mandatory MCP Enforcement Boundary. A client calls the narrow `coffee_station.get_status` Tool; the Go gateway validates the request, obtains an OPA Policy Decision, calls an isolated simulated Protected Resource, validates the response, and returns structured MCP content with the OPA `decision_id` and policy revision.

## Run

```sh
./scripts/smoke.sh
```

The smoke path proves both outcomes:

- `owner` may read `demo-station` and receives `state: ready`.
- The same Tool targeting `real-station` is denied before the coffee-station service is called.
- A caller denied by policy receives an empty Tool catalog as well as execution denial.

The gateway is available at `http://localhost:8080/mcp`; readiness for both OPA and the Protected Resource is available at `http://localhost:8080/healthz`.

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

The current Security Context binds a fixed Subject, Actor, Channel and Turn Capability from deployment configuration. It is a trusted demo fixture shared by callers, not user authentication; OIDC-backed composed identity is deliberately deferred to ticket 02.
