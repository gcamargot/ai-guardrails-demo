package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/replaydemo"
)

func main() {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	handler := replaydemo.NewHandler(replaydemo.Config{
		QwenURL: envconfig.Must("QWEN_URL"), InsecureLockURL: envconfig.Must("INSECURE_LOCK_URL"),
		InsecureLockCredential: envconfig.Must("INSECURE_LOCK_CREDENTIAL"), SecureGatewayURL: envconfig.Must("SECURE_GATEWAY_MCP_URL"),
		TokenEndpoint: envconfig.Must("KEYCLOAK_TOKEN_URL"), OIDCClientID: envconfig.Must("OIDC_CLIENT_ID"),
		OIDCClientSecret: envconfig.Must("OIDC_CLIENT_SECRET"), ExternalUsername: envconfig.Must("EXTERNAL_USERNAME"),
		ExternalPassword: envconfig.Must("EXTERNAL_PASSWORD"), AuditRecordsURL: envconfig.Must("AUDIT_RECORDS_URL"), HTTPClient: httpClient,
	})
	server := &http.Server{Addr: ":8093", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("prompt-rule exploit replay listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
