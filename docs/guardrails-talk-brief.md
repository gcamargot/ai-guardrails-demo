# Agent Tool Guardrails: From Prompt Rules to Enforced Policy

## Purpose

Audience: the full DevOps and Cloud department, with IAM and API knowledge but no assumed MCP background.

Thesis: an agent does not receive authority because it is intelligent or knows a Tool. Every action is authorized from authenticated identity, policy, context and normalized arguments immediately before execution.

Threat model: the model and all model output are untrusted. Protected Resources remain safe when a model is mistaken, hallucinating, prompt-injected or deliberately manipulated.

Target duration: 30 minutes of presentation and 5–10 minutes of questions.

## System shape

```text
Telegram / Codex
       |
       v
trusted identity + per-turn capability
       |
       v
Go MCP gateway ------> OPA/Rego
   |        |          policy decision + decision_id
   |        +--------> audit/telemetry
   |        +--------> Vault credentials
   v
isolated MCP adapters
   |
   +--> demo Calendar / Outlook / smart home / dev resources
```

The gateway is the only component able to reach the adapters. It acts as an MCP server for agents and a controlled client of internal adapters. It owns authentication, schema and semantic validation, authorization, obligations, proxying and audit; conversational logic remains outside it.

## Request envelope

```json
{
  "security_context": {
    "subject": "user:nahtao",
    "actor": "agent:telegram",
    "channel": "telegram",
    "turn_capabilities": ["outlook.read"],
    "issued_at": "...",
    "expires_at": "...",
    "signature": "..."
  },
  "model_interpretation": {
    "request_summary": "Summarize email X",
    "suggested_model": "qwen",
    "intent": "email_read"
  }
}
```

The Security Context is established by trusted infrastructure. The Model Interpretation is validated as data and has no authority. Model routing is constrained by an allowlist; the primary live model is local Qwen, with Codex used as a second MCP client.

## Authorization matrix

| Subject | Actor | Permitted capability |
|---|---|---|
| Owner | Telegram agent | Outlook read; smart-home actions only with a scoped capability and exact approval |
| Owner | Coding agent | Development Tools; never smart lock |
| External Subject | Telegram agent | Free/Busy View and Meeting Proposal |
| Unknown Subject | Any | No Tool Calls |
| Approval Authority | Internal | Emit an Approval for the exact reviewed operation; no Tool access |

The effective permission is the intersection of Subject, Actor, Channel, Turn Capability, Tool, normalized arguments and relevant context. MCP client metadata is observational and never proof of identity.

## Tool contract

Examples of allowed narrow Tools:

- `calendar.get_availability`
- `meeting.propose`
- `meeting.approve`
- `outlook.search`
- `outlook.read_message`
- `smart_lock.unlock`
- `dev.read_repository`

There are no generic HTTP, shell, Graph API or arbitrary Home Assistant tools. Each Tool has strict input and output schemas, rejects unknown fields, applies semantic constraints, and is revalidated by its adapter. Discovery is filtered by identity, but execution is always authorized again.

The response path is controlled as strictly as the request path:

```text
validate request -> authorize -> execute -> validate response -> redact -> audit
```

## Obligations and state

The first implementation supports `allow`, `deny` and `require_confirmation`. The Approval Authority emits an Approval that binds Subject, Actor, Tool, normalized arguments, trace, expiry and nonce; it is signed, short-lived and single-use. The gateway verifies and consumes it before execution. Argument changes require a new Approval, and effects use idempotency keys.

Sensitive capabilities are granted through explicit Telegram buttons or deterministic commands. The classifier can propose a capability but cannot grant it. State remains local for the single-instance demo; Redis is the stated evolution for atomic nonce consumption, rate limiting and high availability.

## Scenarios

### External meeting coordination

An External Subject can query only a bounded Free/Busy View, within a limited future window and working hours. They can submit a Meeting Proposal with identity, reason and contact details, but only the Owner's exact Approval creates an event. Rate limiting prevents spam and schedule enumeration.

### Outlook and untrusted content

Only the Owner can search or read a specifically requested email. Email content is marked untrusted and cannot become user intent or expand the turn's capabilities. Any effect derived from an email requires a new, explicit user interaction and authorization.

### Smart lock

Unlocking the demo lock requires all of: Owner Subject, Telegram Actor, Telegram Channel, `smart_lock.unlock` Turn Capability, the fixed demo device and an exact active Approval. A coding agent cannot unlock it even while acting for the Owner.

### Codex

Codex connects to the same gateway over Streamable HTTP and authenticates with OAuth. Local tool allowlists and approvals improve UX and protect the Codex user; gateway enforcement protects the resource uniformly across all clients. Codex does not discover the smart-lock Tool, and a crafted direct call is still denied.

## Demo narrative

1. Open with an insecure prompt rule: an external message or malicious email induces `smart_lock.unlock`, and the simulated lock opens.
2. Introduce the mandatory gateway and repeat the attack; OPA denies it with a visible trace.
3. Let an External Subject view free/busy information and submit a Meeting Proposal; show the exact Owner Approval before event creation.
4. Let the Owner read an email containing prompt injection; show that no additional Tool can execute in the read-only turn.
5. Connect Codex, use an allowed development Tool, then demonstrate discovery filtering and server-side denial for the smart lock.

Use a dedicated calendar, prepared mailbox, simulated lock and test identities. The live path runs locally with Qwen and Docker Compose. Backups are: preloaded model responses, then a short recording or screenshots correlated with the same trace identifiers.

## Operations and governance

- Missing identity, unavailable OPA or unavailable approval service produces fail-closed behavior for every Tool Call, including availability reads.
- OPA decisions and gateway spans are correlated; logs contain identities, Tool, normalized non-sensitive arguments, rule, policy revision, obligations, outcome and timing.
- Tokens, secrets, email bodies, full prompts and sensitive event data never enter audit logs; sensitive values use references or hashes.
- Policies live in Git, require review, have positive and negative tests, and ship as versioned signed bundles. The talk explains this GitOps path and shows tests rather than deploying a policy live.
- Platform/Security owns the gateway, decision contract and mandatory controls. Resource owners define capabilities and propose policies. Sensitive changes require both reviewers. Clients may restrict locally but cannot broaden server permissions.

## Demo-ready checks

- An External Subject sees free/busy data but no event details.
- An External Subject proposes but cannot create a meeting.
- The Owner approves one exact operation; replay fails.
- Codex neither discovers nor successfully calls the smart lock.
- Email prompt injection cannot cause another Tool Call.
- A model-provided identity is ignored.
- Unknown or malformed arguments are rejected.
- OPA outage produces deny.
- Agents cannot reach adapters directly.
- Logs contain no secrets or email bodies.

## Talk structure

| Time | Segment |
|---:|---|
| 3 min | Controlled compromise of prompt-only protection |
| 5 min | What is and is not an Agent Tool Guardrail |
| 8 min | Trust boundaries, identity and authorization architecture |
| 8 min | End-to-end secure demo |
| 4 min | Observability, tests, fail-closed and ownership |
| 2 min | Conclusions |

Visible code is limited to one narrow Tool schema, one Rego policy combining Subject, Actor, capability and Tool, and tests showing allow and deny cases. The full gateway and Compose deployment remain supporting material.

## Closing checklist

1. Who requested the action, and how is that proven?
2. Which agent is acting, and what capabilities does it have?
3. Are the Tool and arguments minimal and valid?
4. Who authorizes immediately before the effect?
5. Can the decision be reconstructed without exposing sensitive data?

> If the model can grant itself permission, it isn't a guardrail.

## Deliberate evolutions

- Redis for shared state, atomic approvals, distributed rate limiting and replicas.
- Kubernetes NetworkPolicies for production isolation.
- SPIFFE/SPIRE for workload identity.
- Additional contextual conditions such as presence, time, MFA and alarm state.
- Richer obligations such as field-level filtering, quotas and dry-run requirements.
