# Use capability-oriented tools and exact approvals

The gateway exposes narrow, intention-oriented Tools instead of generic HTTP, shell, Graph API or home-automation escape hatches. Inputs and outputs have strict schemas and semantic constraints; sensitive Effects require an Approval bound to the normalized operation, expiry and one-time nonce because broad tools and generic confirmations make meaningful policy enforcement impractical.

## Consequences

Tool discovery is filtered for usability but every call is authorized again. Responses are minimized and validated before reaching a model. Any change to approved arguments requires a new Approval, and retries require idempotency protection.
