package main

import (
	"log"
	"net/http"

	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/policybundle"
)

func main() {
	handler, err := policybundle.NewHandler(policybundle.Config{
		ValidPath:   envconfig.Must("POLICY_BUNDLE_FILE"),
		InvalidPath: envconfig.Must("POLICY_INVALID_BUNDLE_FILE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Print("policy Bundle Service listening on :8091")
	if err := http.ListenAndServe(":8091", handler); err != nil {
		log.Fatal(err)
	}
}
