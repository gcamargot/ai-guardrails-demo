package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/oauthfacade"
)

func main() {
	server := &http.Server{
		Addr: ":8082", Handler: oauthfacade.NewHandler(envconfig.Must("OAUTH_BACKEND_URL")),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	log.Printf("Codex OAuth compatibility facade listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
