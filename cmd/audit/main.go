package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/auditserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
)

func main() {
	server := &http.Server{Addr: ":8089", Handler: auditserver.NewDemoHandler(envconfig.Must("DEMO_RESET_CREDENTIAL")), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("demo audit collector listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
