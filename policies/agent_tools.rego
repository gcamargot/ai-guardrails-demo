package agent_tools

default decision := {
	"allow":           false,
	"policy_revision": "ticket-01",
	"reason":          "default_deny",
}

eligible_owner_tool if {
	input.security_context.subject == "owner"
	input.security_context.actor == "demo-mcp-client"
	input.security_context.channel == "streamable-http"
	input.security_context.turn_capabilities[_] == "coffee_station.read"
	input.tool == "coffee_station.get_status"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-01",
	"reason":          "owner_demo_station",
} if {
	eligible_owner_tool
	input.operation == "execute"
	input.arguments.station_id == "demo-station"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-01",
	"reason":          "owner_tool_discovery",
} if {
	eligible_owner_tool
	input.operation == "discover"
}
