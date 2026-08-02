package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/auditserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	resetCredential, err := vaultclient.DemoResetCredentialFromTokenFile(
		context.Background(), envconfig.Must("VAULT_URL"), envconfig.Must("VAULT_TOKEN_FILE"), httpClient,
	)
	if err != nil {
		log.Fatalf("initialize demo reset credential: %v", err)
	}
	server := &http.Server{Addr: ":8089", Handler: auditserver.NewDemoHandler(resetCredential), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("demo audit collector listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
