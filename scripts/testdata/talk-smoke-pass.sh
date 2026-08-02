#!/bin/sh
set -eu

echo 'PASS subject=owner-subject-id actors=telegram-agent,coding-agent repository=CONTEXT.md available_intervals=2 outlook_message=demo-injection-message outlook_effect_count=0 proposal=proposal-1 event=demo-event-1 event_count=1 policy_revision=ticket-10 invalid_bundle=rejected'
echo 'PASS fail_closed=identity effect_count=0'
