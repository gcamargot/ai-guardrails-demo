package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/smartlockserver"
)

func main() {
	server := &http.Server{
		Addr: ":8092", Handler: smartlockserver.NewDemoHandler(
			envconfig.Must("INSECURE_LOCK_CREDENTIAL"), envconfig.Must("DEMO_RESET_CREDENTIAL"),
		), ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("isolated prompt-only smart-lock fixture listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
