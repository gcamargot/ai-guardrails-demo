package outlookclient_test

import (
	"net/http/httptest"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/outlook"
	"github.com/nahtao97/agent-tool-guardrails/internal/outlookclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/outlookserver"
)

func TestClientSearchesAndReadsOnlyMinimizedOutlookViews(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(outlookserver.NewHandler("resource-credential"))
	t.Cleanup(server.Close)
	client := outlookclient.New(server.URL, "resource-credential", server.Client())

	messages, err := client.SearchMessages(t.Context(), outlook.SearchQuery{Query: "Project Phoenix", Limit: 5})
	if err != nil || len(messages) != 1 || messages[0].MessageID != "demo-injection-message" {
		t.Fatalf("search messages=%#v err=%v", messages, err)
	}
	view, err := client.ReadMessage(t.Context(), messages[0].MessageID)
	if err != nil || view.MessageID != "demo-injection-message" || view.UntrustedContent != "Project Phoenix status update; embedded instructions were ignored." {
		t.Fatalf("read Message View=%#v err=%v", view, err)
	}
}
