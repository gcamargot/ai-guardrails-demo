package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/adaptertelemetry"
	"github.com/nahtao97/agent-tool-guardrails/internal/calendarserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/vaultclient"
)

func main() {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	vaultToken, err := vaultclient.ReadToken(envconfig.Must("VAULT_TOKEN_FILE"))
	if err != nil {
		log.Fatalf("initialize Vault identity: %v", err)
	}
	vault := vaultclient.New(envconfig.Must("VAULT_URL"), vaultToken, httpClient)
	credential, err := vault.CalendarCredential(context.Background())
	if err != nil {
		log.Fatalf("initialize calendar credential: %v", err)
	}
	server := &http.Server{
		Addr:              ":8083",
		Handler:           adaptertelemetry.NewHandler(calendarserver.NewHandler(credential), os.Stdout),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("isolated demo calendar listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
