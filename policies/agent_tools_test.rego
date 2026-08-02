package agent_tools_test

import data.agent_tools.decision

all_tools := {
	"calendar.approve_meeting_proposal",
	"calendar.deny_meeting_proposal",
	"calendar.find_availability",
	"calendar.review_meeting_proposal",
	"calendar.submit_meeting_proposal",
	"coffee_station.get_status",
	"dev.read_repository",
	"outlook.read_message",
	"outlook.search_messages",
	"smart_lock.unlock",
}

discovered(context) := {tool |
	tool := all_tools[_]
	result := decision with input as {
		"correlation_id": "matrix-discovery",
		"security_context": context,
		"operation": "discover",
		"tool": tool,
		"arguments": {},
	}
	result.allow
}

test_complete_subject_actor_discovery_matrix if {
	cases := [
		{
			"context": {
				"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
				"turn_capabilities": ["calendar.meeting.approve", "outlook.mail.read", "smart_lock.write"],
			},
			"expected": {
				"calendar.approve_meeting_proposal", "calendar.deny_meeting_proposal",
				"calendar.review_meeting_proposal", "outlook.read_message",
				"outlook.search_messages", "smart_lock.unlock",
			},
		},
		{
			"context": {
				"subject": "owner-subject-id", "actor": "coding-agent", "channel": "streamable-http",
				"turn_capabilities": ["coffee_station.read", "dev.repository.read", "smart_lock.write"],
			},
			"expected": {"coffee_station.get_status", "dev.read_repository"},
		},
		{
			"context": {
				"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram",
				"turn_capabilities": ["calendar.free_busy.read", "calendar.meeting.propose"],
			},
			"expected": {"calendar.find_availability", "calendar.submit_meeting_proposal"},
		},
		{
			"context": {
				"subject": "external-alice-subject-id", "actor": "coding-agent", "channel": "streamable-http",
				"turn_capabilities": ["calendar.free_busy.read", "dev.repository.read", "smart_lock.write"],
			},
			"expected": set(),
		},
		{
			"context": {
				"subject": "unknown", "actor": "telegram-agent", "channel": "telegram",
				"turn_capabilities": ["calendar.free_busy.read", "smart_lock.write"],
			},
			"expected": set(),
		},
		{
			"context": {
				"subject": "unknown", "actor": "coding-agent", "channel": "streamable-http",
				"turn_capabilities": ["dev.repository.read", "smart_lock.write"],
			},
			"expected": set(),
		},
		{
			"context": {
				"subject": "approval-authority", "actor": "internal", "channel": "approval",
				"turn_capabilities": ["calendar.meeting.approve", "smart_lock.write"],
			},
			"expected": set(),
		},
	]

	every case in cases {
		discovered(case.context) == case.expected
	}
}

test_positive_execution_matrix if {
	cases := [
		{
			"context": {"subject": "owner-subject-id", "actor": "coding-agent", "channel": "streamable-http", "turn_capabilities": ["dev.repository.read"]},
			"tool": "dev.read_repository", "arguments": {"path": "CONTEXT.md"}, "obligations": [],
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["outlook.mail.read"]},
			"tool": "outlook.read_message", "arguments": {"message_id": "demo-injection-message"}, "obligations": [],
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["outlook.mail.read"]},
			"tool": "outlook.search_messages", "arguments": {"query": "guardrails", "limit": 5}, "obligations": [],
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "coding-agent", "channel": "streamable-http", "turn_capabilities": ["coffee_station.read"]},
			"tool": "coffee_station.get_status", "arguments": {"station_id": "demo-station"}, "obligations": [],
		},
		{
			"context": {"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.free_busy.read"]},
			"tool": "calendar.find_availability", "arguments": {"start": "2026-08-03T09:00:00Z", "end": "2026-08-03T12:00:00Z"}, "obligations": [],
		},
		{
			"context": {"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.meeting.propose"]},
			"tool": "calendar.submit_meeting_proposal", "arguments": {"start": "2026-08-03T13:00:00Z", "end": "2026-08-03T13:30:00Z", "reason": "Guardrails sync", "contact": "alice@example.invalid"}, "obligations": [],
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.meeting.approve"]},
			"tool": "calendar.review_meeting_proposal", "arguments": {"proposal_id": "proposal-1"}, "obligations": [],
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.meeting.approve"]},
			"tool": "calendar.approve_meeting_proposal", "arguments": {"proposal_id": "proposal-1"}, "obligations": ["exact_approval"],
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.meeting.approve"]},
			"tool": "calendar.deny_meeting_proposal", "arguments": {"proposal_id": "proposal-1"}, "obligations": ["exact_approval"],
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["smart_lock.write"]},
			"tool": "smart_lock.unlock", "arguments": {"device_id": "demo-front-door"}, "obligations": ["exact_approval"],
		},
	]

	every case in cases {
		result := decision with input as {
			"correlation_id": "matrix-execution",
			"security_context": case.context,
			"operation": "execute",
			"tool": case.tool,
			"arguments": case.arguments,
		}
			with time.now_ns as time.parse_rfc3339_ns("2026-08-01T12:00:00Z")
		result.allow
		result.correlation_id == "matrix-execution"
		result.obligations == case.obligations
		result.policy_revision == "ticket-09"
	}
}

test_turn_capabilities_never_expand_authority if {
	cases := [
		{
			"context": {"subject": "owner-subject-id", "actor": "coding-agent", "channel": "streamable-http", "turn_capabilities": ["smart_lock.write"]},
			"tool": "smart_lock.unlock", "arguments": {"device_id": "demo-front-door"},
		},
		{
			"context": {"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["outlook.mail.read"]},
			"tool": "outlook.read_message", "arguments": {"message_id": "demo-injection-message"},
		},
		{
			"context": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": []},
			"tool": "smart_lock.unlock", "arguments": {"device_id": "demo-front-door"},
		},
		{
			"context": {"subject": "approval-authority", "actor": "internal", "channel": "approval", "turn_capabilities": ["smart_lock.write"]},
			"tool": "smart_lock.unlock", "arguments": {"device_id": "demo-front-door"},
		},
	]

	every case in cases {
		result := decision with input as {
			"correlation_id": "matrix-deny-capability",
			"security_context": case.context,
			"operation": "execute",
			"tool": case.tool,
			"arguments": case.arguments,
		}
		not result.allow
		result.correlation_id == "matrix-deny-capability"
		result.obligations == []
		result.policy_revision == "ticket-09"
	}
}

test_argument_constraints_fail_closed if {
	cases := [
		{"tool": "dev.read_repository", "arguments": {"path": ".ssh/id_ed25519"}},
		{"tool": "coffee_station.get_status", "arguments": {"station_id": "real-station"}},
		{"tool": "outlook.read_message", "arguments": {"message_id": "other-message"}},
		{"tool": "outlook.search_messages", "arguments": {"query": "guardrails", "limit": 6}},
		{"tool": "smart_lock.unlock", "arguments": {"device_id": "garage-door"}},
		{"tool": "calendar.submit_meeting_proposal", "arguments": {"start": "2026-08-03T13:00:00Z", "end": "2026-08-03T13:30:00Z", "reason": "", "contact": "alice@example.invalid"}},
		{"tool": "calendar.approve_meeting_proposal", "arguments": {"proposal_id": ""}},
	]
	contexts := {
		"dev.read_repository": {"subject": "owner-subject-id", "actor": "coding-agent", "channel": "streamable-http", "turn_capabilities": ["dev.repository.read"]},
		"coffee_station.get_status": {"subject": "owner-subject-id", "actor": "coding-agent", "channel": "streamable-http", "turn_capabilities": ["coffee_station.read"]},
		"outlook.read_message": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["outlook.mail.read"]},
		"outlook.search_messages": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["outlook.mail.read"]},
		"smart_lock.unlock": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["smart_lock.write"]},
		"calendar.submit_meeting_proposal": {"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.meeting.propose"]},
		"calendar.approve_meeting_proposal": {"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.meeting.approve"]},
	}

	every case in cases {
		not decision.allow with input as {
			"correlation_id": "matrix-deny-arguments",
			"security_context": contexts[case.tool],
			"operation": "execute",
			"tool": case.tool,
			"arguments": case.arguments,
		}
	}

	not decision.allow with input as {
		"correlation_id": "matrix-deny-window",
		"security_context": {"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram", "turn_capabilities": ["calendar.free_busy.read"]},
		"operation": "execute",
		"tool": "calendar.find_availability",
		"arguments": {"start": "2026-08-24T09:00:00Z", "end": "2026-08-24T12:00:00Z"},
	}
		with time.now_ns as time.parse_rfc3339_ns("2026-08-01T12:00:00Z")
}
