package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/democontrol"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
)

func main() {
	handler := democontrol.NewHandler(democontrol.Config{
		Credential: envconfig.Must("DEMO_RESET_CREDENTIAL"), InsecureLockURL: envconfig.Must("INSECURE_LOCK_URL"),
		SecureLockURL: envconfig.Must("SECURE_LOCK_URL"), AuditURL: envconfig.Must("AUDIT_URL"),
		ApprovalURL: envconfig.Must("APPROVAL_AUTHORITY_URL"), HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})
	server := &http.Server{Addr: ":8094", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("isolated demo reset control listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
