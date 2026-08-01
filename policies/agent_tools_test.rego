package agent_tools_test

import data.agent_tools.decision

test_only_owner_telegram_with_explicit_capability_can_read_outlook if {
	read := decision with input as {
		"security_context": {
			"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["outlook.mail.read"],
		},
		"operation": "execute", "tool": "outlook.read_message",
		"arguments": {"message_id": "demo-injection-message"},
	}
	read.allow

	not decision.allow with input as {
		"security_context": {
			"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["outlook.mail.read"],
		},
		"operation": "execute", "tool": "outlook.read_message",
		"arguments": {"message_id": "demo-injection-message"},
	}

	not decision.allow with input as {
		"security_context": {
			"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["calendar.free_busy.read"],
		},
		"operation": "execute", "tool": "outlook.read_message",
		"arguments": {"message_id": "demo-injection-message"},
	}
}

test_owner_can_discover_bounded_outlook_read_tools if {
	search := decision with input as {
		"security_context": {
			"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["outlook.mail.read"],
		},
		"operation": "discover", "tool": "outlook.search_messages",
	}
	search.allow
	read := decision with input as {
		"security_context": {
			"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["outlook.mail.read"],
		},
		"operation": "discover", "tool": "outlook.read_message",
	}
	read.allow
}

test_external_subject_can_submit_proposal_but_not_approve if {
	proposal := decision with input as {
		"security_context": {
			"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["calendar.meeting.propose"],
		},
		"operation": "execute", "tool": "calendar.submit_meeting_proposal",
		"arguments": {"start": "2026-08-03T13:00:00Z", "end": "2026-08-03T13:30:00Z"},
	}
	proposal.allow
	not decision.allow with input as {
		"security_context": {
			"subject": "external-alice-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["calendar.meeting.approve"],
		},
		"operation": "execute", "tool": "calendar.approve_meeting_proposal",
		"arguments": {"proposal_id": "proposal-1"},
	}
}

test_owner_can_review_and_approve_exact_proposal if {
	review := decision with input as {
		"security_context": {
			"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["calendar.meeting.approve"],
		},
		"operation": "execute", "tool": "calendar.review_meeting_proposal",
		"arguments": {"proposal_id": "proposal-1"},
	}
	review.allow
	approve := decision with input as {
		"security_context": {
			"subject": "owner-subject-id", "actor": "telegram-agent", "channel": "telegram",
			"turn_capabilities": ["calendar.meeting.approve"],
		},
		"operation": "execute", "tool": "calendar.approve_meeting_proposal",
		"arguments": {"proposal_id": "proposal-1"},
	}
	approve.allow
}

test_owner_can_read_demo_station if {
	decision == {"allow": true, "policy_revision": "ticket-05", "reason": "owner_demo_station"} with input as {
		"security_context": {
			"subject": "owner-subject-id",
			"actor": "telegram-agent",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "execute",
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "demo-station"},
	}
}

test_coding_agent_can_read_for_same_owner if {
	decision == {"allow": true, "policy_revision": "ticket-05", "reason": "owner_demo_station"} with input as {
		"security_context": {
			"subject": "owner-subject-id",
			"actor": "coding-agent",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "execute",
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "demo-station"},
	}
}

test_external_subject_is_denied if {
	decision == {"allow": false, "policy_revision": "ticket-05", "reason": "default_deny"} with input as {
		"security_context": {
			"subject": "external",
			"actor": "telegram-agent",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "execute",
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "demo-station"},
	}
}

test_other_station_is_denied if {
	decision == {"allow": false, "policy_revision": "ticket-05", "reason": "default_deny"} with input as {
		"security_context": {
			"subject": "owner-subject-id",
			"actor": "telegram-agent",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "execute",
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "real-station"},
	}
}

test_owner_can_discover_tool if {
	decision == {"allow": true, "policy_revision": "ticket-05", "reason": "owner_tool_discovery"} with input as {
		"security_context": {
			"subject": "owner-subject-id",
			"actor": "telegram-agent",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "discover",
		"tool": "coffee_station.get_status",
	}
}

test_external_subject_cannot_discover_tool if {
	not decision.allow with input as {
		"security_context": {
			"subject": "external",
			"actor": "telegram-agent",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "discover",
		"tool": "coffee_station.get_status",
	}
}

test_external_subject_can_find_availability_in_working_window if {
	decision == {"allow": true, "policy_revision": "ticket-05", "reason": "external_free_busy"} with input as {
		"security_context": {
			"subject": "external-alice-subject-id",
			"actor": "telegram-agent",
			"channel": "telegram",
			"turn_capabilities": ["calendar.free_busy.read"],
		},
		"operation": "execute",
		"tool": "calendar.find_availability",
		"arguments": {
			"start": "2026-08-03T09:00:00Z",
			"end": "2026-08-03T12:00:00Z",
		},
	} with time.now_ns as time.parse_rfc3339_ns("2026-08-01T12:00:00Z")
}

test_external_subject_is_denied_outside_future_window if {
	not decision.allow with input as {
		"security_context": {
			"subject": "external-alice-subject-id",
			"actor": "telegram-agent",
			"channel": "telegram",
			"turn_capabilities": ["calendar.free_busy.read"],
		},
		"operation": "execute",
		"tool": "calendar.find_availability",
		"arguments": {
			"start": "2026-08-24T09:00:00Z",
			"end": "2026-08-24T12:00:00Z",
		},
	} with time.now_ns as time.parse_rfc3339_ns("2026-08-01T12:00:00Z")
}

test_external_subject_can_discover_only_availability if {
	decision == {"allow": true, "policy_revision": "ticket-05", "reason": "external_availability_discovery"} with input as {
		"security_context": {
			"subject": "external-alice-subject-id",
			"actor": "telegram-agent",
			"channel": "telegram",
			"turn_capabilities": ["calendar.free_busy.read"],
		},
		"operation": "discover",
		"tool": "calendar.find_availability",
	}

	not decision.allow with input as {
		"security_context": {
			"subject": "external-alice-subject-id",
			"actor": "telegram-agent",
			"channel": "telegram",
			"turn_capabilities": ["calendar.free_busy.read"],
		},
		"operation": "discover",
		"tool": "coffee_station.get_status",
	}
}

test_external_subject_is_denied_outside_working_hours if {
	not decision.allow with input as {
		"security_context": {
			"subject": "external-alice-subject-id",
			"actor": "telegram-agent",
			"channel": "telegram",
			"turn_capabilities": ["calendar.free_busy.read"],
		},
		"operation": "execute",
		"tool": "calendar.find_availability",
		"arguments": {
			"start": "2026-08-03T08:00:00Z",
			"end": "2026-08-03T10:00:00Z",
		},
	} with time.now_ns as time.parse_rfc3339_ns("2026-08-01T12:00:00Z")
}

test_external_subject_is_denied_after_working_hours_end if {
	not decision.allow with input as {
		"security_context": {
			"subject": "external-alice-subject-id",
			"actor": "telegram-agent",
			"channel": "telegram",
			"turn_capabilities": ["calendar.free_busy.read"],
		},
		"operation": "execute",
		"tool": "calendar.find_availability",
		"arguments": {
			"start": "2026-08-03T16:00:00Z",
			"end": "2026-08-03T17:30:00Z",
		},
	} with time.now_ns as time.parse_rfc3339_ns("2026-08-01T12:00:00Z")
}
