package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/telegramadapter"
)

func main() {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	subject := telegramadapter.Subject(requiredEnvironment("EXTERNAL_SUBJECT"))
	userID, err := strconv.ParseInt(requiredEnvironment("TELEGRAM_USER_ID"), 10, 64)
	if err != nil {
		log.Fatalf("parse verified Telegram user ID: %v", err)
	}
	availability := telegramadapter.NewGatewayClient(telegramadapter.GatewayClientConfig{
		Endpoint:      requiredEnvironment("GATEWAY_MCP_URL"),
		TokenEndpoint: requiredEnvironment("KEYCLOAK_TOKEN_URL"),
		ClientID:      "telegram-agent",
		ClientSecret:  requiredEnvironment("TELEGRAM_OIDC_CLIENT_SECRET"),
		Subject:       subject,
		Username:      requiredEnvironment("EXTERNAL_USERNAME"),
		Password:      requiredEnvironment("EXTERNAL_PASSWORD"),
		HTTPClient:    httpClient,
	})
	handler := telegramadapter.NewHandler(telegramadapter.Config{
		WebhookSecret: requiredEnvironment("TELEGRAM_WEBHOOK_SECRET"),
		VerifiedUsers: map[telegramadapter.TelegramUserID]telegramadapter.Subject{
			telegramadapter.TelegramUserID(userID): subject,
		},
		ClassifierURL: requiredEnvironment("QWEN_URL") + "/classify",
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

func requiredEnvironment(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("required environment variable %s is missing", name)
	}
	return value
}
