package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/calendarserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	vault := vaultclient.New(requiredEnvironment("VAULT_URL"), requiredEnvironment("VAULT_TOKEN"), httpClient)
	credential, err := vault.CalendarCredential(context.Background())
	if err != nil {
		log.Fatalf("initialize calendar credential: %v", err)
	}
	server := &http.Server{
		Addr:              ":8083",
		Handler:           calendarserver.NewHandler(credential),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("isolated demo calendar listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("required environment variable %s is missing", name)
	}
	return value
}
