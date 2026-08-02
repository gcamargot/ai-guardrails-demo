package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/developmentserver"
	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
)

func main() {
	content, err := os.ReadFile(envconfig.Must("REPOSITORY_DOCUMENT_FILE"))
	if err != nil {
		log.Fatalf("read allowlisted repository artifact: %v", err)
	}
	server := &http.Server{
		Addr: ":8090", Handler: developmentserver.NewHandler(string(content)),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	log.Printf("demo development repository listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
