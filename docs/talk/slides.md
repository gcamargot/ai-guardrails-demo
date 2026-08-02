# Agent Tool Guardrails: From Prompt Rules to Enforced Policy

DevOps & Cloud · demo local, identidades sintéticas, recursos simulados

<!-- segment:compromise minutes:3 -->
## 0:00–3:00 — El compromiso controlado

### Prompt Rule exploit: parece un control… hasta que deja de serlo

- Mensaje externo: contenido hostil preparado.
- Qwen clasifica la intención como `smart_lock.unlock`.
- El Actor vulnerable confía en la salida del modelo.
- Resultado: el lock simulado cambia de `locked` a `unlocked`.

### Repetimos exactamente la misma intención

<!-- demo-scenario:exploit -->

| Camino | Identidad preservada | Control | Resultado |
|---|---|---|---|
| Prompt-only | No | Prompt Rule | Effect producido |
| Enforced | External Subject real | OPA antes del adapter | Deny, cero Effects |

La diferencia no es un prompt mejor. Es una frontera que el Actor no puede evitar.

<!-- segment:definition minutes:5 -->
## 3:00–8:00 — Qué es un guardrail

### MCP mental model

Un cliente MCP descubre Tools y solicita Tool Calls. El servidor publica contratos tipados; conocer una Tool no concede autoridad para ejecutarla.

Cliente/Actor → MCP gateway → Tool tipada → Protected Resource

### Prompt Rule versus Guardrail

| Prompt Rule | Guardrail |
|---|---|
| Orienta al modelo | Restringe una Tool Call |
| Vive en contexto no confiable | Vive fuera del modelo |
| Cada cliente la replica | La Enforcement Boundary aplica a todos |
| Puede ser ignorada | Falla cerrada si no puede decidir |

### Una Tool estrecha hace posible una política útil

<!-- visible-code:tool-schema -->
```json
{
  "name": "smart_lock.unlock",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"const": "demo-front-door"},
      "trace_id": {"type": "string"},
      "approval": {"type": "string"}
    },
    "required": ["device_id", "trace_id", "approval"],
    "additionalProperties": false
  }
}
```

No hay Tool genérica de HTTP, shell, Graph API ni Home Assistant.

<!-- segment:architecture minutes:8 -->
## 8:00–16:00 — Trust boundary, identidad y autorización

### Dos planos que nunca se mezclan

**Security Context — confiable:** Subject, Actor, Channel y Turn Capability, derivados de identidad autenticada.

**Model Interpretation — no confiable:** intención, resumen y modelo sugerido. Es dato; no identidad ni autoridad.

La autorización efectiva intersecta:

**Subject + Actor + Channel + Turn Capability + Tool + arguments**

### Flujo de enforcement

Telegram / Codex
→ Keycloak: identidad firmada
→ Go MCP gateway: autenticar, normalizar, validar
→ OPA/Rego: Policy Decision
→ Approval Authority: obligación exacta cuando aplica
→ adapter aislado: Effect
→ audit: trace + correlation + decision + revision

Vault es la única fuente de credenciales downstream. Los Actors no tienen ruta de red a los adapters.

### La política representativa

<!-- visible-code:rego-policy -->
```rego
eligible_owner_smart_lock if {
  input.security_context.subject == "owner-subject-id"
  input.security_context.actor == "telegram-agent"
  input.security_context.channel == "telegram"
  input.security_context.turn_capabilities[_] == "smart_lock.write"
  input.tool == "smart_lock.unlock"
  input.arguments.device_id == "demo-front-door"
}

authorization := {"allow": true, "obligations": ["exact_approval"]} if {
  eligible_owner_smart_lock
}

authorization := {"allow": false, "reason": "smart_lock_owner_subject_required"} if {
  input.tool == "smart_lock.unlock"
  input.security_context.subject != "owner-subject-id"
}
```

### Ownership compartido

- **Platform/Security:** Enforcement Boundary, contrato de decisión y firma/publicación de políticas.
- **Protected Resource owner:** capacidades, constraints y revisión de autoridad sobre su recurso.
- Cambios sensibles: ambos reviewers.
- Equipos de clientes: pueden restringir localmente; nunca ampliar permisos del servidor.

<!-- segment:demo minutes:8 -->
## 16:00–24:00 — Demo segura end-to-end

### 1. Exploit y replay seguro

Misma intención y argumentos; External Subject preservado; condición fallida visible y correlacionada; adapter protegido sin Effects.

### 2. Coordinar sin revelar calendario

<!-- demo-scenario:meeting -->

Un External Subject obtiene sólo Free/Busy View, crea una Meeting Proposal y espera. El Owner revisa Tool y argumentos normalizados; una Approval exacta, temporal y single-use permite crear un único evento.

### 3. Leer no significa obedecer

<!-- demo-scenario:outlook -->

El Owner concede una Turn Capability read-only, lee un mensaje preparado con Outlook prompt injection y recibe contenido minimizado marcado como Untrusted Content. No se autoriza ninguna Tool posterior y el contador de Effects permanece en cero.

### 4. El segundo cliente no crea una segunda política

<!-- demo-scenario:codex -->

Codex usa `dev.read_repository`. Su allowlist y aprobación local son defensa adicional. No descubre `smart_lock.unlock`; una llamada MCP construida manualmente recibe Codex denial en la misma Enforcement Boundary.

### Sólo mostramos dos decisiones

<!-- visible-code:policy-tests -->
```rego
test_owner_telegram_unlock_is_allowed if {
  result := authorization with input as owner_telegram_unlock
  result.allow
}

test_external_subject_unlock_is_denied if {
  result := authorization with input as external_subject_unlock
  not result.allow
  result.reason == "smart_lock_owner_subject_required"
}
```

<!-- segment:operations minutes:4 -->
## 24:00–28:00 — Operarlo como plataforma

### Evidencia sin filtrar secretos

- `trace_id`, `correlation_id`, `decision_id` y policy revision unen gateway, OPA y adapter.
- Audit conserva identidad clasificada, Tool, argumentos seguros, regla, outcome y timing.
- Tokens, approvals, cuerpos de email y prompts completos no entran en logs.

### Fail closed es comportamiento verificable

- Identity, OPA o Approval Authority caídos → deny, incluso para Free/Busy.
- Input u output malformado → deny antes de cruzar la frontera.
- Bundle inválido → OPA conserva la última revisión buena.
- Probes de red → Telegram, Qwen y Codex no alcanzan adapters.

### GitOps y evolución

Rego formateado + compile estricto + tests positivos/negativos + owners + bundle firmado. Redis, NetworkPolicies y SPIFFE/SPIRE son evoluciones, no dependencias ocultas de esta demo.

<!-- segment:conclusion minutes:2 -->
## 28:00–30:00 — Cierre

### Checklist para cualquier Agent Tool

<!-- closing-checklist:start -->
1. ¿Quién es el Subject y cómo se prueba?
2. ¿Qué Actor actúa y con qué Turn Capability?
3. ¿La Tool y sus argumentos son mínimos y válidos?
4. ¿Quién autoriza inmediatamente antes del Effect?
5. ¿Podemos reconstruir la Policy Decision sin exponer datos sensibles?
<!-- closing-checklist:end -->

> If the model can grant itself permission, it isn't a guardrail.

Preguntas: 5–10 minutos, fuera de los 30 minutos de presentación.
