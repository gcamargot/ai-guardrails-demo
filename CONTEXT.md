# Agent Tool Authorization

Este contexto define el lenguaje usado para razonar sobre agentes que solicitan acciones sobre recursos protegidos. Distingue interpretación probabilística, identidad confiable y autorización aplicada antes de producir efectos.

## Trust and identity

**Subject**:
Persona autenticada en cuyo nombre se procesa una petición.
_Avoid_: User field, username, requester string

**Owner**:
Subject con autoridad personal sobre los recursos protegidos del homelab.
_Avoid_: Admin, superuser

**External Subject**:
Subject autenticado que no es el Owner y posee únicamente capacidades públicas explícitas.
_Avoid_: Guest, anonymous user

**Unknown Subject**:
Origen cuya identidad no pudo verificarse; no posee capacidades para invocar tools.
_Avoid_: External Subject, unauthenticated user

**Actor**:
Agente o aplicación autenticada que intenta actuar en nombre de un Subject.
_Avoid_: Model, client name

**Channel**:
Medio autenticado por el que se originó una petición, como Telegram o un coding agent.
_Avoid_: Actor, source string

**Security Context**:
Aserción confiable que vincula Subject, Actor, Channel y capacidades vigentes para una interacción.
_Avoid_: Model context, prompt metadata

**Model Interpretation**:
Representación no confiable de la intención solicitada, incluida su clasificación y la recomendación de modelo.
_Avoid_: Security Context, authorization request

**Untrusted Content**:
Datos de procedencia externa que pueden ser leídos, pero nunca tratados como intención ni autoridad del Subject.
_Avoid_: User instruction, trusted context

## Capabilities and actions

**Turn Capability**:
Autorización temporal que limita las acciones máximas disponibles durante una interacción; nunca se amplía dentro del mismo turno.
_Avoid_: Permission, role

**Tool**:
Capacidad estrecha, tipada y orientada a una intención que un Actor puede solicitar.
_Avoid_: Endpoint, arbitrary API, function

**Tool Call**:
Intento concreto de invocar una Tool con argumentos normalizados.
_Avoid_: Action, request

**Protected Resource**:
Dato, dispositivo o servicio cuyo acceso está mediado por políticas.
_Avoid_: Backend, integration

**Effect**:
Cambio observable producido sobre un Protected Resource.
_Avoid_: Tool Call, result

**Meeting Proposal**:
Solicitud pendiente para reservar un horario, sin producir aún un evento de calendario.
_Avoid_: Meeting, calendar event

## Policy and enforcement

**Guardrail**:
Control verificable aplicado fuera del modelo que restringe una Tool Call o su resultado.
_Avoid_: Prompt Rule, model instruction

**Prompt Rule**:
Instrucción que orienta el comportamiento del modelo pero no constituye una frontera de seguridad.
_Avoid_: Guardrail, authorization policy

**Policy**:
Regla determinista que evalúa el contexto confiable y la operación solicitada.
_Avoid_: Prompt, model policy

**Policy Decision**:
Resultado auditable de evaluar una Tool Call, expresado como allow, deny u obligaciones pendientes.
_Avoid_: Model decision, recommendation

**Obligation**:
Condición que debe satisfacerse antes de que una Policy Decision permita producir un Effect.
_Avoid_: Suggestion, warning

**Approval**:
Autorización humana exacta, temporal y de un solo uso, vinculada al Subject, Actor, Tool y argumentos de una Tool Call.
_Avoid_: Consent flag, generic confirmation

**Approval Authority**:
Componente confiable que atestigua una Approval, pero no ejecuta Tools ni accede a Protected Resources.
_Avoid_: Approval Actor, executor

**Enforcement Boundary**:
Límite obligatorio que ningún Actor puede evitar al acceder a Protected Resources.
_Avoid_: Client guardrail, prompt wrapper

**Free/Busy View**:
Representación mínima de disponibilidad que revela intervalos posibles sin exponer contenido de eventos.
_Avoid_: Calendar read, event list
