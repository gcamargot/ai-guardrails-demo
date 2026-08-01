package agent_tools_test

import data.agent_tools.decision

test_owner_can_read_demo_station if {
	decision with input as {
		"security_context": {
			"subject": "owner",
			"actor": "demo-mcp-client",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "execute",
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "demo-station"},
	} == {"allow": true, "policy_revision": "ticket-01", "reason": "owner_demo_station"}
}

test_external_subject_is_denied if {
	decision with input as {
		"security_context": {
			"subject": "external",
			"actor": "demo-mcp-client",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "execute",
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "demo-station"},
	} == {"allow": false, "policy_revision": "ticket-01", "reason": "default_deny"}
}

test_other_station_is_denied if {
	decision with input as {
		"security_context": {
			"subject": "owner",
			"actor": "demo-mcp-client",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "execute",
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "real-station"},
	} == {"allow": false, "policy_revision": "ticket-01", "reason": "default_deny"}
}

test_owner_can_discover_tool if {
	decision with input as {
		"security_context": {
			"subject": "owner",
			"actor": "demo-mcp-client",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "discover",
		"tool": "coffee_station.get_status",
	} == {"allow": true, "policy_revision": "ticket-01", "reason": "owner_tool_discovery"}
}

test_external_subject_cannot_discover_tool if {
	not decision.allow with input as {
		"security_context": {
			"subject": "external",
			"actor": "demo-mcp-client",
			"channel": "streamable-http",
			"turn_capabilities": ["coffee_station.read"],
		},
		"operation": "discover",
		"tool": "coffee_station.get_status",
	}
}
