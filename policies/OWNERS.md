# Policy Artifact Ownership

Platform/Security approval: required

Resource owner approval: required

Every sensitive Policy change requires two independent approvals before publishing:

1. Platform/Security owns the Enforcement Boundary, policy quality gates, signing and OPA distribution.
2. The relevant resource owner owns the intended authority and argument constraints for their Protected Resource.

| Policy area | Required resource owner |
|---|---|
| Calendar availability and Meeting Proposals | Calendar owner |
| Outlook read access | Messaging owner |
| Smart Lock Effects | Smart Home owner |
| Development repository reads | Developer Experience owner |
| Shared identity, discovery or default-deny behavior | Every affected resource owner |

The publisher records both approvals in the pull request. Neither group can self-approve for the other, and the policy artifact pipeline refuses a source tree without these ownership requirements.
