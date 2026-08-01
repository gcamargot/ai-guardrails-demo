package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/coffeestationclient"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/opaclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	handler := gateway.NewHandler(gateway.Dependencies{
		SecurityContext: gateway.SecurityContext{
			Subject:          gateway.Subject(environment("DEMO_SUBJECT", "unknown")),
			Actor:            gateway.Actor(environment("DEMO_ACTOR", "unknown")),
			Channel:          gateway.Channel(environment("DEMO_CHANNEL", "unknown")),
			TurnCapabilities: []gateway.Capability{"coffee_station.read"},
		},
		Policy: opaclient.New(environment("OPA_URL", "http://127.0.0.1:8181"), httpClient),
		CoffeeStation: coffeestationclient.New(
			environment("COFFEE_STATION_URL", "http://127.0.0.1:8081"),
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

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
