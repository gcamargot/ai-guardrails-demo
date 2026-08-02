package codexconfig_test

import (
	"os"
	"strings"
	"testing"
)

func TestProjectConfigNarrowsCodexWithoutClaimingServerAuthority(t *testing.T) {
	contents, err := os.ReadFile("../../examples/codex/config.toml")
	if err != nil {
		t.Fatalf("read project Codex config: %v", err)
	}
	config := string(contents)
	for _, required := range []string{
		`[mcp_servers.agent_tool_guardrails]`,
		`url = "http://127.0.0.1:8080/mcp"`,
		`auth = "oauth"`,
		`required = true`,
		`scopes = ["dev.repository.read"]`,
		`enabled_tools = ["dev.read_repository"]`,
		`default_tools_approval_mode = "prompt"`,
	} {
		if !strings.Contains(config, required) {
			t.Errorf("Codex config does not contain %q", required)
		}
	}
	if strings.Contains(config, "smart_lock.unlock") {
		t.Fatal("Codex client allowlist contains the smart-lock Tool")
	}
	if strings.Contains(config, "oauth_resource") {
		t.Fatal("Codex config duplicates the resource already advertised by RFC 9728 metadata")
	}
}
