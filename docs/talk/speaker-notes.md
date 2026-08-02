# Speaker notes — Agent Tool Guardrails

Estas notas usan los términos canónicos de `CONTEXT.md`. No presentar `Model Interpretation` como identidad, `Prompt Rule` como Guardrail ni una Tool Call como un Effect.

## 0:00–3:00 — Compromise

- Abrir directamente con `talk-demo.sh run --mode live` y el contraste prompt-only/enforced.
- No explicar todavía todos los componentes. Preguntar: “¿Qué cambió si la intención fue idéntica?”.
- Respuesta: la identidad real llegó a una Enforcement Boundary obligatoria.
- Corte a los 3:00 aunque haya preguntas; anotarlas para el final.

## 3:00–8:00 — Definition

- Explicar MCP para una audiencia con experiencia en APIs: descubrimiento más invocación de contratos tipados.
- Una Prompt Rule mejora comportamiento; un Guardrail restringe autoridad.
- Mostrar solamente el schema de `smart_lock.unlock`. Subrayar `const`, campos requeridos y rechazo de propiedades extra.
- El problema organizacional: replicar controles en Codex, Copilot y cada agente no escala.

## 8:00–16:00 — Architecture

- Separar visualmente Security Context y Model Interpretation.
- Recorrer Subject, Actor, Channel, Turn Capability, Tool y argumentos; ninguno puede ser completado por el modelo.
- Señalar el único camino de red: gateway → adapter. OPA decide; Vault custodia secretos; Keycloak firma identidad.
- Approval Authority atestigua una Approval exacta pero no ejecuta Tools.
- Mostrar sólo la política Rego representativa.
- Ownership: Platform/Security + Protected Resource owner; doble revisión para cambios sensibles.

## 16:00–24:00 — Demo

- Usar el runbook. Nombrar el outcome antes de cada comando para que la audiencia sepa qué mirar.
- Exploit: lock inseguro cambia; replay seguro preserva External Subject y muestra regla/trace.
- Meeting Proposal: revelar intervalos libres, nunca títulos; propuesta no equivale a evento; Approval exacta crea uno.
- Outlook: el resumen se marca Untrusted Content y el contador de Effects no cambia.
- Codex: primero Tool permitida, luego ausencia en discovery y denial server-side de la llamada construida.
- Mostrar al final sólo los dos tests Rego enfocados.

## 24:00–28:00 — Operations

- Leer una sola línea de evidencia correlacionada, no un muro de logs.
- Nombrar los cinco fail-closed checks ya automatizados.
- Explicar política como artefacto firmado y revisado, no editar Rego en vivo.
- Evoluciones en una frase: Redis, Kubernetes NetworkPolicies y SPIFFE/SPIRE.

## 28:00–30:00 — Conclusion

- Hacer las cinco preguntas del checklist como mecanismo reutilizable por los equipos.
- Cerrar literalmente con: “If the model can grant itself permission, it isn't a guardrail.”
- Detener la presentación. Abrir 5–10 minutos de preguntas.

## Señales de corte

Si un segmento excede su presupuesto, omitir detalle, nunca un escenario ni el cierre. El modo `preloaded` reemplaza latencia del modelo; `evidence` reemplaza el entorno completo. No improvisar contra cuentas ni dispositivos reales.
