package system.log_test

import data.system.log.mask

test_decision_logs_remove_sensitive_content if {
	paths := mask with input as {"input": {"arguments": {
		"approval": "signed-approval",
		"body": "private email body",
		"contact": "alice@example.invalid",
		"prompt": "full model prompt",
		"query": "private mailbox query",
		"reason": "private meeting reason",
		"secret": "downstream credential",
		"token": "bearer token",
	}}}

	paths == {
		"/input/arguments/approval",
		"/input/arguments/body",
		"/input/arguments/contact",
		"/input/arguments/prompt",
		"/input/arguments/query",
		"/input/arguments/reason",
		"/input/arguments/secret",
		"/input/arguments/token",
	}
}
