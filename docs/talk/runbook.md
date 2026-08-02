# Runbook de la charla

## Invariantes de seguridad

- Usar únicamente el entorno Docker Compose aislado del repositorio.
- Las identidades, mailbox, calendario, Approval Authority y ambos locks son fixtures sintéticos.
- No conectar Home Assistant, Outlook ni calendarios reales.
- No pegar tokens, approvals, prompts completos ni cuerpos de email en slides o terminal.
- Mantener `main` en una revisión probada; no desplegar una policy en vivo.

## Preflight — 15 minutos antes

1. Ejecutar `./scripts/talk-package.sh validate`.
2. Ejecutar `./scripts/rehearse-talk.sh verify docs/talk/rehearsal.json` y leer el estado humano.
3. Verificar Docker con `docker compose config --quiet`.
4. Ejecutar una vez `./scripts/talk-demo.sh run --mode live` fuera de pantalla.
5. Dejar abiertos slides, una terminal grande y `docs/talk/fallback/evidence.md`.

## Secuencia visible — 8 minutos

Ejecutar `./scripts/talk-demo.sh run --mode live`. La salida tiene cuatro registros ordenados y sanitizados:

1. `exploit`: Effect sólo en el lock inseguro y denial correlacionado en el camino enforced.
2. `meeting`: Meeting Proposal seguida por Approval exacta y un solo evento sintético.
3. `outlook`: lectura minimizada de Untrusted Content y cero Effects derivados.
4. `codex`: Tool de desarrollo permitida y smart lock denegado por servidor.

No abrir logs completos. Mostrar únicamente los identificadores seguros emitidos por el runner.

## Fallbacks

1. Si el modelo local está lento, ejecutar `./scripts/talk-demo.sh run --mode preloaded`.
2. Si Docker o el entorno no responde, ejecutar `./scripts/talk-demo.sh run --mode evidence` y abrir la secuencia de evidencias correlacionadas.

Los tres modos mantienen el mismo orden y contrato observable para evitar cambiar la narración bajo presión.

## Recuperación

- El runner live usa el smoke reproducible y siempre ejecuta teardown.
- Si se interrumpe manualmente: `docker compose down --remove-orphans --volumes`.
- Volver a un estado conocido repitiendo el runner; nunca reparar fixtures manualmente durante la charla.

## Después del ensayo

Registrar tiempos observados en `docs/talk/rehearsal.json`. El verificador sólo valida datos observados: no convierte una plantilla o estimación en un ensayo aprobado.
