package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoint := environment("GATEWAY_MCP_URL", "http://127.0.0.1:8080/mcp")
	tokenEndpoint := environment("KEYCLOAK_TOKEN_URL", "http://127.0.0.1:8082/realms/agent-tools/protocol/openid-connect/token")
	if status := unauthenticatedStatus(ctx, endpoint); status != http.StatusUnauthorized {
		log.Fatalf("unauthenticated MCP status = %d, want %d", status, http.StatusUnauthorized)
	}

	telegramToken := obtainToken(ctx, tokenEndpoint, "telegram-agent", "telegram-demo-secret")
	codingToken := obtainToken(ctx, tokenEndpoint, "coding-agent", "coding-demo-secret")
	telegramClaims := readClaims(telegramToken)
	codingClaims := readClaims(codingToken)
	if telegramClaims.Subject == "" || telegramClaims.Subject != codingClaims.Subject {
		log.Fatalf("OAuth clients did not preserve Subject: telegram=%q coding=%q", telegramClaims.Subject, codingClaims.Subject)
	}
	if telegramClaims.Actor != "telegram-agent" || codingClaims.Actor != "coding-agent" {
		log.Fatalf("OAuth clients were not distinguishable Actors: telegram=%q coding=%q", telegramClaims.Actor, codingClaims.Actor)
	}

	telegramDecision := callCoffeeStation(ctx, endpoint, telegramToken, nil)
	codingDecision := callCoffeeStation(ctx, endpoint, codingToken, mcp.Meta{
		"model_interpretation": map[string]any{
			"user":         "attacker",
			"actor":        "telegram-agent",
			"capabilities": []string{"smart_lock.write"},
		},
	})

	fmt.Printf(
		"PASS subject=%s actors=%s,%s telegram_decision=%v coding_decision=%v policy_revision=ticket-02\n",
		telegramClaims.Subject,
		telegramClaims.Actor,
		codingClaims.Actor,
		telegramDecision,
		codingDecision,
	)
}

func obtainToken(ctx context.Context, endpoint, clientID, clientSecret string) string {
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"username":      {"owner"},
		"password":      {"owner-demo-password"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatalf("create %s token request: %v", clientID, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("request %s token: %v", clientID, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("request %s token: HTTP %d", clientID, response.StatusCode)
	}
	var document struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil || document.AccessToken == "" {
		log.Fatalf("decode %s access token: token_present=%t err=%v", clientID, document.AccessToken != "", err)
	}
	return document.AccessToken
}

func callCoffeeStation(ctx context.Context, endpoint, token string, meta mcp.Meta) any {
	client := mcp.NewClient(&mcp.Implementation{Name: "compose-smoke", Version: "v0.2.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		DisableStandaloneSSE: true,
		HTTPClient: oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
		})),
	}, nil)
	if err != nil {
		log.Fatalf("connect to authenticated gateway: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Meta:      meta,
		Name:      "coffee_station.get_status",
		Arguments: map[string]any{"station_id": "demo-station"},
	})
	if err != nil {
		log.Fatalf("authenticated Tool Call: %v", err)
	}
	if result.IsError {
		log.Fatalf("authenticated Tool Call was denied: %v", result.GetError())
	}
	output, ok := result.StructuredContent.(map[string]any)
	if !ok || output["state"] != "ready" {
		log.Fatalf("unexpected authenticated result: %#v", result.StructuredContent)
	}
	if result.Meta["policy_revision"] != "ticket-02" {
		log.Fatalf("unexpected policy revision: %v", result.Meta["policy_revision"])
	}
	return result.Meta["decision_id"]
}

func unauthenticatedStatus(ctx context.Context, endpoint string) int {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{}`))
	if err != nil {
		log.Fatalf("create unauthenticated request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Fatalf("send unauthenticated request: %v", err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

type tokenClaims struct {
	Subject string `json:"sub"`
	Actor   string `json:"azp"`
}

func readClaims(token string) tokenClaims {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		log.Fatal("Keycloak returned a malformed access token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		log.Fatalf("decode access token claims: %v", err)
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		log.Fatalf("parse access token claims: %v", err)
	}
	return claims
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
