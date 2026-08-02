# 11 — Package and rehearse the 30-minute talk

**What to build:** A speaker can deliver the complete “Agent Tool Guardrails: From Prompt Rules to Enforced Policy” narrative in 30 minutes using the working demo, concise slides and prepared fallback material, leaving 5–10 minutes for questions.

**Blocked by:** 04 — Let an External Subject submit a Meeting Proposal for exact Owner Approval; 05 — Let the Owner read Outlook without acting on Untrusted Content; 07 — Connect Codex to the same Enforcement Boundary; 09 — Observe decisions and prove fail-closed operation; 10 — Replay the prompt-only exploit against enforced policy.

**Status:** ready-for-human

- [ ] The talk follows the agreed 3/5/8/8/4/2-minute structure and completes within 30 minutes in rehearsal.
- [x] Slides explain the MCP mental model, trust boundary, composed identity, enforcement flow and shared ownership model.
- [x] Visible code is limited to one narrow Tool schema, one representative Rego policy and focused allow/deny tests.
- [x] The live sequence covers the exploit, Meeting Proposal approval, Outlook prompt injection and Codex denial scenarios.
- [x] Synthetic identities, mailbox, calendar and simulated lock prevent disclosure or real-world Effects.
- [x] Preloaded model responses and a trace-correlated recording or screenshot sequence provide two fallback levels.
- [x] The closing checklist and “If the model can grant itself permission, it isn't a guardrail” appear in the final section.

## Comments

- Packaged the local Markdown slides, speaker notes and runbook with public validation and demo commands. The three live/preloaded/evidence modes share four sanitized scenario outcomes; the real live mode passed the isolated end-to-end smoke.
- Added a strict rehearsal gate for the 3/5/8/8/4/2 structure, 30-minute maximum and 5–10-minute Q&A. `docs/talk/rehearsal.json` deliberately remains `pending`; a speaker must record an actual rehearsal before the first acceptance criterion can be checked.
