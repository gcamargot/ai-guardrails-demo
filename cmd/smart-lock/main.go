package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/adaptertelemetry"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/smartlockserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	vaultToken, err := vaultclient.ReadToken(envconfig.Must("VAULT_TOKEN_FILE"))
	if err != nil {
		log.Fatalf("initialize Vault identity: %v", err)
	}
	credential, err := vaultclient.New(envconfig.Must("VAULT_URL"), vaultToken, httpClient).SmartLockCredential(context.Background())
	if err != nil {
		log.Fatalf("initialize smart-lock credential: %v", err)
	}
	server := &http.Server{
		Addr: ":8088", Handler: adaptertelemetry.NewHandler(
			smartlockserver.NewDemoHandler(credential, envconfig.Must("DEMO_RESET_CREDENTIAL")), os.Stdout,
		), ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("isolated simulated smart lock listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
