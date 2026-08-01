package agent_tools

default decision := {
	"allow": false,
	"reason": "default_deny",
}

decision := {
	"allow": true,
	"reason": "owner_demo_station",
} if {
	input.security_context.subject == "owner"
	input.tool == "coffee_station.get_status"
	input.arguments.station_id == "demo-station"
}
