package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
)

func main() {
	handler := approvalauthority.NewHandler(approvalauthority.Config{
		SigningKey:         []byte(envconfig.Must("APPROVAL_SIGNING_KEY")),
		IssuerCredential:   envconfig.Must("APPROVAL_ISSUER_CREDENTIAL"),
		ConsumerCredential: envconfig.Must("APPROVAL_CONSUMER_CREDENTIAL"),
		OwnerSubject:       envconfig.Must("OWNER_SUBJECT"),
		TTL:                2 * time.Minute,
		StateFile:          envconfig.Must("APPROVAL_STATE_FILE"),
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
