package system.log

sensitive_argument_keys := {
	"approval",
	"body",
	"contact",
	"prompt",
	"query",
	"reason",
	"secret",
	"token",
}

mask contains sprintf("/input/arguments/%s", [key]) if {
	some key in sensitive_argument_keys
	key in object.keys(input.input.arguments)
}
