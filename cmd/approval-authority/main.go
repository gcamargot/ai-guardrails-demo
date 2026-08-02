package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	vaultToken, err := vaultclient.ReadToken(envconfig.Must("VAULT_TOKEN_FILE"))
	if err != nil {
		log.Fatalf("initialize Vault identity: %v", err)
	}
	resetCredential, err := vaultclient.New(envconfig.Must("VAULT_URL"), vaultToken, httpClient).DemoResetCredential(context.Background())
	if err != nil {
		log.Fatalf("initialize demo reset credential: %v", err)
	}
	ttl := 2 * time.Minute
	if configured := os.Getenv("APPROVAL_TTL"); configured != "" {
		parsed, err := time.ParseDuration(configured)
		if err != nil || parsed <= 0 {
			log.Fatalf("invalid APPROVAL_TTL %q", configured)
		}
		ttl = parsed
	}
	handler := approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey:          []byte(envconfig.Must("APPROVAL_SIGNING_KEY")),
		IssuerCredential:    envconfig.Must("APPROVAL_ISSUER_CREDENTIAL"),
		ConsumerCredential:  envconfig.Must("APPROVAL_CONSUMER_CREDENTIAL"),
		OwnerSubject:        envconfig.Must("OWNER_SUBJECT"),
		DemoResetCredential: resetCredential,
		TTL:                 ttl,
		StateFile:           envconfig.Must("APPROVAL_STATE_FILE"),
	})
	server := &http.Server{
		Addr: ":8086", Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	log.Printf("Approval Authority listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
