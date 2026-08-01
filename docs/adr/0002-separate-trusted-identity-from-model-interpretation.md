# Separate trusted identity from model interpretation

Requests carry a signed Security Context separately from the Model Interpretation. Trusted adapters establish the Subject, Actor and Channel, while models may classify intent and suggest routing but cannot assert identity, grant permissions or expand Turn Capabilities; sensitive capabilities arise only from explicit commands, UI actions or exact approvals.

## Considered Options

- A flat classifier-produced JSON envelope was rejected because an LLM-generated `user` field is data, not authentication.
- Allowing an agent to infer sensitive authority from natural language was rejected because injected or hallucinated intent can be indistinguishable from genuine intent at execution time.

## Consequences

Authorization evaluates the intersection of Subject, Actor, Channel, Turn Capability, Tool and arguments. Reading Untrusted Content cannot authorize a later effect, and a new explicit interaction is required to obtain additional capabilities.
