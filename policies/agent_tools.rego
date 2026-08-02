package agent_tools

policy_revision := data.policy_metadata.revision

policy_decision(allow, reason, obligations) := {
	"allow": allow,
	"correlation_id": object.get(input, "correlation_id", "missing"),
	"obligations": obligations,
	"policy_revision": policy_revision,
	"reason": reason,
}

default authorization := {"allow": false, "obligations": [], "reason": "default_deny"}

decision := policy_decision(authorization.allow, authorization.reason, authorization.obligations)

eligible_owner_coding_repository if {
	input.security_context.subject == "owner-subject-id"
	input.security_context.actor == "coding-agent"
	input.security_context.channel == "streamable-http"
	input.security_context.turn_capabilities[_] == "dev.repository.read"
	input.tool == "dev.read_repository"
}

authorization := {"allow": true, "obligations": [], "reason": "owner_coding_repository_read"} if {
	eligible_owner_coding_repository
	input.operation == "discover"
}

authorization := {"allow": true, "obligations": [], "reason": "owner_coding_repository_read"} if {
	eligible_owner_coding_repository
	input.operation == "execute"
	input.arguments == {"path": "CONTEXT.md"}
}

eligible_owner_outlook if {
	input.security_context.subject == "owner-subject-id"
	input.security_context.actor == "telegram-agent"
	input.security_context.channel == "telegram"
	input.security_context.turn_capabilities[_] == "outlook.mail.read"
	input.tool in {"outlook.search_messages", "outlook.read_message"}
}

authorization := {"allow": true, "obligations": [], "reason": "owner_outlook_read_discovery"} if {
	eligible_owner_outlook
	input.operation == "discover"
}

authorization := {"allow": true, "obligations": [], "reason": "owner_exact_outlook_message"} if {
	eligible_owner_outlook
	input.operation == "execute"
	input.tool == "outlook.read_message"
	input.arguments.message_id == "demo-injection-message"
}

authorization := {"allow": true, "obligations": [], "reason": "owner_bounded_outlook_search"} if {
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

authorization := {"allow": true, "obligations": [], "reason": "owner_demo_station"} if {
	eligible_owner_tool
	input.operation == "execute"
	input.arguments.station_id == "demo-station"
}

authorization := {"allow": true, "obligations": [], "reason": "owner_tool_discovery"} if {
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
	end <= now + ((((14 * 24) * 60) * 60) * 1000000000)
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

authorization := {"allow": true, "obligations": [], "reason": "external_free_busy"} if {
	eligible_external_availability
	input.operation == "execute"
	availability_window_allowed
}

authorization := {"allow": true, "obligations": [], "reason": "external_availability_discovery"} if {
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

authorization := {"allow": true, "obligations": [], "reason": "external_meeting_proposal"} if {
	eligible_external_proposal
	input.operation == "discover"
}

authorization := {"allow": true, "obligations": [], "reason": "external_meeting_proposal"} if {
	eligible_external_proposal
	input.operation == "execute"
	meeting_proposal_arguments_allowed
}

meeting_proposal_arguments_allowed if {
	start := time.parse_rfc3339_ns(input.arguments.start)
	end := time.parse_rfc3339_ns(input.arguments.end)
	end > start
	end <= start + (((2 * 60) * 60) * 1000000000)
	is_string(input.arguments.reason)
	input.arguments.reason != ""
	count(input.arguments.reason) <= 200
	is_string(input.arguments.contact)
	input.arguments.contact != ""
	count(input.arguments.contact) <= 320
}

eligible_owner_meeting_approval if {
	input.security_context.subject == "owner-subject-id"
	input.security_context.actor == "telegram-agent"
	input.security_context.channel == "telegram"
	input.security_context.turn_capabilities[_] == "calendar.meeting.approve"
	input.tool in {"calendar.review_meeting_proposal", "calendar.approve_meeting_proposal", "calendar.deny_meeting_proposal"}
}

authorization := {"allow": true, "obligations": ["exact_approval"], "reason": "owner_exact_meeting_approval"} if {
	eligible_owner_meeting_approval
	input.operation == "discover"
}

authorization := {"allow": true, "obligations": [], "reason": "owner_meeting_review"} if {
	eligible_owner_meeting_approval
	input.operation == "execute"
	input.tool == "calendar.review_meeting_proposal"
	proposal_reference_allowed
}

authorization := {"allow": true, "obligations": ["exact_approval"], "reason": "owner_exact_meeting_approval"} if {
	eligible_owner_meeting_approval
	input.operation == "execute"
	input.tool in {"calendar.approve_meeting_proposal", "calendar.deny_meeting_proposal"}
	proposal_reference_allowed
}

proposal_reference_allowed if {
	is_string(input.arguments.proposal_id)
	regex.match("^proposal-[a-zA-Z0-9-]+$", input.arguments.proposal_id)
}

eligible_owner_smart_lock if {
	input.security_context.subject == "owner-subject-id"
	input.security_context.actor == "telegram-agent"
	input.security_context.channel == "telegram"
	input.security_context.turn_capabilities[_] == "smart_lock.write"
	input.tool == "smart_lock.unlock"
}

authorization := {"allow": false, "obligations": [], "reason": "smart_lock_owner_subject_required"} if {
	input.tool == "smart_lock.unlock"
	input.security_context.subject != "owner-subject-id"
}

authorization := {"allow": true, "obligations": ["exact_approval"], "reason": "owner_exact_smart_lock"} if {
	eligible_owner_smart_lock
	input.operation == "discover"
}

authorization := {"allow": true, "obligations": ["exact_approval"], "reason": "owner_exact_smart_lock"} if {
	eligible_owner_smart_lock
	input.operation == "execute"
	input.arguments == {"device_id": "demo-front-door"}
}
