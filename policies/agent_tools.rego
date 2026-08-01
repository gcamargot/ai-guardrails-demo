package agent_tools

default decision := {
	"allow":           false,
	"policy_revision": "ticket-05",
	"reason":          "default_deny",
}

eligible_owner_outlook if {
	input.security_context.subject == "owner-subject-id"
	input.security_context.actor == "telegram-agent"
	input.security_context.channel == "telegram"
	input.security_context.turn_capabilities[_] == "outlook.mail.read"
	input.tool in {"outlook.search_messages", "outlook.read_message"}
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "owner_outlook_read_discovery",
} if {
	eligible_owner_outlook
	input.operation == "discover"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "owner_exact_outlook_message",
} if {
	eligible_owner_outlook
	input.operation == "execute"
	input.tool == "outlook.read_message"
	input.arguments.message_id == "demo-injection-message"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "owner_bounded_outlook_search",
} if {
	eligible_owner_outlook
	input.operation == "execute"
	input.tool == "outlook.search_messages"
	is_string(input.arguments.query)
	input.arguments.query != ""
	count(input.arguments.query) <= 100
	input.arguments.limit >= 1
	input.arguments.limit <= 5
}

eligible_owner_tool if {
	input.security_context.subject == "owner-subject-id"
	input.security_context.actor in {"telegram-agent", "coding-agent"}
	input.security_context.channel == "streamable-http"
	input.security_context.turn_capabilities[_] == "coffee_station.read"
	input.tool == "coffee_station.get_status"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "owner_demo_station",
} if {
	eligible_owner_tool
	input.operation == "execute"
	input.arguments.station_id == "demo-station"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "owner_tool_discovery",
} if {
	eligible_owner_tool
	input.operation == "discover"
}

eligible_external_availability if {
	input.security_context.subject == "external-alice-subject-id"
	input.security_context.actor == "telegram-agent"
	input.security_context.channel == "telegram"
	input.security_context.turn_capabilities[_] == "calendar.free_busy.read"
	input.tool == "calendar.find_availability"
}

availability_window_allowed if {
	start := time.parse_rfc3339_ns(input.arguments.start)
	end := time.parse_rfc3339_ns(input.arguments.end)
	now := time.now_ns()
	start >= now
	end > start
	end <= now + (14 * 24 * 60 * 60 * 1000000000)
	time.weekday(start) in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
	time.weekday(end) == time.weekday(start)
	start_clock := time.clock([start, "UTC"])
	end_clock := time.clock([end, "UTC"])
	start_clock[0] >= 9
	working_day_end(end_clock)
}

working_day_end(clock) if {
	clock[0] < 17
}

working_day_end(clock) if {
	clock == [17, 0, 0]
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "external_free_busy",
} if {
	eligible_external_availability
	input.operation == "execute"
	availability_window_allowed
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "external_availability_discovery",
} if {
	eligible_external_availability
	input.operation == "discover"
}

eligible_external_proposal if {
	input.security_context.subject == "external-alice-subject-id"
	input.security_context.actor == "telegram-agent"
	input.security_context.channel == "telegram"
	input.security_context.turn_capabilities[_] == "calendar.meeting.propose"
	input.tool == "calendar.submit_meeting_proposal"
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "external_meeting_proposal",
} if {
	eligible_external_proposal
	input.operation in {"discover", "execute"}
}

eligible_owner_meeting_approval if {
	input.security_context.subject == "owner-subject-id"
	input.security_context.actor == "telegram-agent"
	input.security_context.channel == "telegram"
	input.security_context.turn_capabilities[_] == "calendar.meeting.approve"
	input.tool in {"calendar.review_meeting_proposal", "calendar.approve_meeting_proposal", "calendar.deny_meeting_proposal"}
}

decision := {
	"allow":           true,
	"policy_revision": "ticket-05",
	"reason":          "owner_exact_meeting_approval",
} if {
	eligible_owner_meeting_approval
	input.operation in {"discover", "execute"}
}
