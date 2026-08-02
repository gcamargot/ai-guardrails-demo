package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/democontrol"
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
	handler := democontrol.NewHandler(democontrol.Config{
		Credential: resetCredential, InsecureLockURL: envconfig.Must("INSECURE_LOCK_URL"),
		SecureLockURL: envconfig.Must("SECURE_LOCK_URL"), AuditURL: envconfig.Must("AUDIT_URL"),
		ApprovalURL: envconfig.Must("APPROVAL_AUTHORITY_URL"), HTTPClient: httpClient,
	})
	server := &http.Server{Addr: ":8094", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("isolated demo reset control listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
