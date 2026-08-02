package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/adaptertelemetry"
	"github.com/nahtao97/agent-tool-guardrails/internal/coffeestationserver"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           adaptertelemetry.NewHandler(coffeestationserver.NewHandler(), os.Stdout),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("simulated coffee station listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
