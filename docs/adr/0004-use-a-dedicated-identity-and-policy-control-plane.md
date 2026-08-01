# Use a dedicated identity and policy control plane

The demo uses Keycloak as the common OIDC issuer, OPA/Rego as the deterministic policy engine, and Vault as the only source of downstream credentials. These components were chosen to keep authentication, authorization and secret custody independent from the Go MCP gateway and to make each control inspectable to a DevOps/Cloud audience.

## Considered Options

- OpenFGA was not selected as the primary engine because the policies must inspect contextual tool arguments as well as subject-resource relationships.
- Cedar was considered viable, but OPA/Rego offers a more familiar policy-as-code and decision-logging story for the intended audience.
- Credentials embedded in agents or prompts were rejected because they bypass least privilege and can leak through context or logs.

## Consequences

The gateway validates issuer, audience, signature, expiry and scopes, and sends normalized policy input to OPA. Workload identity through SPIFFE/SPIRE remains a production evolution rather than part of the demo.
