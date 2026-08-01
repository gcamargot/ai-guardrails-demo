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
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/oidcauth"
	"github.com/nahtao97/agent-tool-guardrails/internal/opaclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	vaultToken, err := vaultclient.ReadToken(envconfig.Must("VAULT_TOKEN_FILE"))
	if err != nil {
		log.Fatalf("initialize Vault identity: %v", err)
	}
	vault := vaultclient.New(envconfig.Must("VAULT_URL"), vaultToken, httpClient)
	calendarCredential, err := vault.CalendarCredential(context.Background())
	if err != nil {
		log.Fatalf("initialize calendar credential: %v", err)
	}
	authenticator, err := oidcauth.New(context.Background(), oidcauth.Config{
		Issuer:          envconfig.Must("OIDC_ISSUER"),
		Audience:        envconfig.Must("OIDC_AUDIENCE"),
		RequiredScopes:  requiredCapabilities("OIDC_REQUIRED_SCOPES"),
		DiscoveryClient: httpClient,
	})
	if err != nil {
		log.Fatalf("initialize OIDC authentication: %v", err)
	}
	handler := gateway.NewHandler(gateway.Dependencies{
		Identity: authenticator,
		Channel:  gateway.Channel(envconfig.Must("AUTH_CHANNEL")),
		Policy:   opaclient.New(environment("OPA_URL", "http://127.0.0.1:8181"), httpClient),
		CoffeeStation: coffeestationclient.New(
			environment("COFFEE_STATION_URL", "http://127.0.0.1:8081"),
			httpClient,
		),
		Calendar: calendarclient.New(
			envconfig.Must("CALENDAR_URL"),
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
	value := envconfig.Must(name)
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

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
