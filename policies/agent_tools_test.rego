package agent_tools_test

import data.agent_tools.decision

test_owner_can_read_demo_station if {
	decision == {"allow": true, "policy_revision": "ticket-02", "reason": "owner_demo_station"} with input as {
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
	decision == {"allow": true, "policy_revision": "ticket-02", "reason": "owner_demo_station"} with input as {
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
	decision == {"allow": false, "policy_revision": "ticket-02", "reason": "default_deny"} with input as {
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
	decision == {"allow": false, "policy_revision": "ticket-02", "reason": "default_deny"} with input as {
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
	decision == {"allow": true, "policy_revision": "ticket-02", "reason": "owner_tool_discovery"} with input as {
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
