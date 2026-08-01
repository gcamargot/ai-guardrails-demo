package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/calendarclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/coffeestationclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/oidcauth"
	"github.com/nahtao97/agent-tool-guardrails/internal/opaclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	vault := vaultclient.New(requiredEnvironment("VAULT_URL"), requiredEnvironment("VAULT_TOKEN"), httpClient)
	calendarCredential, err := vault.CalendarCredential(context.Background())
	if err != nil {
		log.Fatalf("initialize calendar credential: %v", err)
	}
	authenticator, err := oidcauth.New(context.Background(), oidcauth.Config{
		Issuer:          requiredEnvironment("OIDC_ISSUER"),
		Audience:        requiredEnvironment("OIDC_AUDIENCE"),
		RequiredScopes:  requiredCapabilities("OIDC_REQUIRED_SCOPES"),
		DiscoveryClient: httpClient,
	})
	if err != nil {
		log.Fatalf("initialize OIDC authentication: %v", err)
	}
	handler := gateway.NewHandler(gateway.Dependencies{
		Identity: authenticator,
		Channel:  gateway.Channel(requiredEnvironment("AUTH_CHANNEL")),
		Policy:   opaclient.New(environment("OPA_URL", "http://127.0.0.1:8181"), httpClient),
		CoffeeStation: coffeestationclient.New(
			environment("COFFEE_STATION_URL", "http://127.0.0.1:8081"),
			httpClient,
		),
		Calendar: calendarclient.New(
			requiredEnvironment("CALENDAR_URL"),
			calendarCredential,
			httpClient,
		),
	})

	server := &http.Server{
		Addr:              ":" + environment("PORT", "8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("agent tool gateway listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func requiredCapabilities(name string) []gateway.Capability {
	value := requiredEnvironment(name)
	parts := strings.Split(value, ",")
	capabilities := make([]gateway.Capability, 0, len(parts))
	for _, part := range parts {
		if capability := strings.TrimSpace(part); capability != "" {
			capabilities = append(capabilities, gateway.Capability(capability))
		}
	}
	if len(capabilities) == 0 {
		log.Fatalf("required environment variable %s contains no capabilities", name)
	}
	return capabilities
}

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("required environment variable %s is missing", name)
	}
	return value
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
