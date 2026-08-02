package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/adaptertelemetry"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/outlookserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	vaultToken, err := vaultclient.ReadToken(envconfig.Must("VAULT_TOKEN_FILE"))
	if err != nil {
		log.Fatalf("initialize Vault identity: %v", err)
	}
	vault := vaultclient.New(envconfig.Must("VAULT_URL"), vaultToken, httpClient)
	credential, err := vault.OutlookCredential(context.Background())
	if err != nil {
		log.Fatalf("initialize Outlook credential: %v", err)
	}
	server := &http.Server{
		Addr: ":8087", Handler: adaptertelemetry.NewHandler(outlookserver.NewHandler(credential), os.Stdout), ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("isolated read-only demo Outlook listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
