## Agent skills

### Issue tracker

Issues live as local Markdown files under `.scratch/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the five canonical triage states with their default names. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context project with `CONTEXT.md` at the root and ADRs under `docs/adr/`. See `docs/agents/domain.md`.

### GitHub publishing identity

- Create commits as `Gaston Camargo <63078256+gcamargot@users.noreply.github.com>` so GitHub attributes them to `@gcamargot`.
- Push to `git@github.com:gcamargot/ai-guardrails-demo.git` using `/home/nahtao97/.ssh/id_ed25519` with `IdentitiesOnly=yes`.
- Keep `main` tracking `origin/main`; never rewrite published history unless the user explicitly requests it.
