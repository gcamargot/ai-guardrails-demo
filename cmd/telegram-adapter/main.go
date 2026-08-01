package main

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/envconfig"
	"github.com/nahtao97/agent-tool-guardrails/internal/telegramadapter"
)

func main() {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	subject := telegramadapter.Subject(envconfig.Must("EXTERNAL_SUBJECT"))
	userID, err := strconv.ParseInt(envconfig.Must("TELEGRAM_USER_ID"), 10, 64)
	if err != nil {
		log.Fatalf("parse verified Telegram user ID: %v", err)
	}
	availability := telegramadapter.NewGatewayClient(telegramadapter.GatewayClientConfig{
		Endpoint:      envconfig.Must("GATEWAY_MCP_URL"),
		TokenEndpoint: envconfig.Must("KEYCLOAK_TOKEN_URL"),
		ClientID:      "telegram-agent",
		ClientSecret:  envconfig.Must("TELEGRAM_OIDC_CLIENT_SECRET"),
		Subject:       subject,
		Username:      envconfig.Must("EXTERNAL_USERNAME"),
		Password:      envconfig.Must("EXTERNAL_PASSWORD"),
		HTTPClient:    httpClient,
	})
	handler := telegramadapter.NewHandler(telegramadapter.Config{
		WebhookSecret: envconfig.Must("TELEGRAM_WEBHOOK_SECRET"),
		VerifiedUsers: map[telegramadapter.TelegramUserID]telegramadapter.Subject{
			telegramadapter.TelegramUserID(userID): subject,
		},
		ClassifierURL: envconfig.Must("QWEN_URL") + "/classify",
		HTTPClient:    httpClient,
		Availability:  availability,
	})
	server := &http.Server{
		Addr:              ":8084",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log.Printf("trusted Telegram adapter listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
