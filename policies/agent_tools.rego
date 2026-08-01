package agent_tools

default decision := {
	"allow":           false,
	"policy_revision": "ticket-01",
	"reason":          "default_deny",
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-01",
	"reason":          "owner_demo_station",
} if {
	input.security_context.subject == "owner"
	input.security_context.actor == "demo-mcp-client"
	input.security_context.channel == "streamable-http"
	input.security_context.turn_capabilities[_] == "coffee_station.read"
	input.operation == "execute"
	input.tool == "coffee_station.get_status"
	input.arguments.station_id == "demo-station"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-01",
	"reason":          "owner_tool_discovery",
} if {
	input.security_context.subject == "owner"
	input.security_context.actor == "demo-mcp-client"
	input.security_context.channel == "streamable-http"
	input.security_context.turn_capabilities[_] == "coffee_station.read"
	input.operation == "discover"
	input.tool == "coffee_station.get_status"
}
