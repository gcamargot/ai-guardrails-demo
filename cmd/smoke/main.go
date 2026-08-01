package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	endpoint := os.Getenv("GATEWAY_MCP_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080/mcp"
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "compose-smoke", Version: "v0.1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		log.Fatalf("connect to gateway: %v", err)
	}
	defer session.Close()

	allowed, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		log.Fatalf("allowed Tool Call: %v", err)
	}
	if allowed.IsError {
		log.Fatalf("allowed Tool Call was denied: %v", allowed.GetError())
	}
	output, ok := allowed.StructuredContent.(map[string]any)
	if !ok || output["state"] != "ready" {
		log.Fatalf("unexpected allowed result: %#v", allowed.StructuredContent)
	}
	if allowed.Meta["policy_revision"] != "ticket-01" {
		log.Fatalf("unexpected policy revision: %v", allowed.Meta["policy_revision"])
	}

	denied, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "real-station"},
	})
	if err != nil {
		log.Fatalf("denied Tool Call: %v", err)
	}
	if !denied.IsError {
		log.Fatal("policy-denied Tool Call succeeded")
	}
	if denied.Meta["decision_id"] == nil {
		log.Fatal("denied Tool Call has no decision_id")
	}

	fmt.Printf(
		"PASS policy_revision=%v allow_decision=%v deny_decision=%v\n",
		allowed.Meta["policy_revision"],
		allowed.Meta["decision_id"],
		denied.Meta["decision_id"],
	)
}
