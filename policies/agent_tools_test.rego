package agent_tools_test

import data.agent_tools.decision

test_owner_can_read_demo_station if {
	decision with input as {
		"security_context": {"subject": "owner"},
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "demo-station"},
	} == {"allow": true, "reason": "owner_demo_station"}
}

test_external_subject_is_denied if {
	decision with input as {
		"security_context": {"subject": "external"},
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "demo-station"},
	} == {"allow": false, "reason": "default_deny"}
}

test_other_station_is_denied if {
	decision with input as {
		"security_context": {"subject": "owner"},
		"tool": "coffee_station.get_status",
		"arguments": {"station_id": "real-station"},
	} == {"allow": false, "reason": "default_deny"}
}
