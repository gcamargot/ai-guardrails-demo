package agent_tools_test

import data.agent_tools.decision

test_owner_can_read_demo_station if {
	decision == {"allow": true, "policy_revision": "ticket-03", "reason": "owner_demo_station"} with input as {
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
	decision == {"allow": true, "policy_revision": "ticket-03", "reason": "owner_demo_station"} with input as {
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
	decision == {"allow": false, "policy_revision": "ticket-03", "reason": "default_deny"} with input as {
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
	decision == {"allow": false, "policy_revision": "ticket-03", "reason": "default_deny"} with input as {
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
	decision == {"allow": true, "policy_revision": "ticket-03", "reason": "owner_tool_discovery"} with input as {
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
	decision == {"allow": true, "policy_revision": "ticket-03", "reason": "external_free_busy"} with input as {
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
	decision == {"allow": true, "policy_revision": "ticket-03", "reason": "external_availability_discovery"} with input as {
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
