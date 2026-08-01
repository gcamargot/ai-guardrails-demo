# Enforce tool policy at a mandatory gateway

All agents access protected resources through a central MCP gateway, and downstream adapters are network-isolated from those agents. The model, prompt, classifier output, and client-side approvals are treated as untrusted or bypassable; therefore the gateway validates and authorizes every discovery and execution request immediately before access, fails closed when it cannot decide, and applies output controls before returning data.

## Considered Options

- Client-only guardrails were rejected because they are distributed across tools, inconsistently administered, and bypassable by a modified client.
- Prompt-only rules were rejected because a model can be mistaken or manipulated.
- Direct access to downstream MCP servers was rejected because it would make enforcement optional.

## Consequences

Client controls remain useful as an additional user-facing defense, but server policy is authoritative. The gateway becomes security-critical and must expose health, audit, and policy revision data.
