package telegramadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nahtao97/agent-tool-guardrails/internal/oidcclient"
	"golang.org/x/oauth2"
)

type GatewayClientConfig struct {
	Endpoint      string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Subject       Subject
	Username      string
	Password      string
	HTTPClient    *http.Client
}

type GatewayClient struct {
	config GatewayClientConfig
}

func NewGatewayClient(config GatewayClientConfig) *GatewayClient {
	return &GatewayClient{config: config}
}

func (client *GatewayClient) FindAvailability(
	ctx context.Context,
	identity TrustedTelegramIdentity,
	query AvailabilityQuery,
) ([]AvailableInterval, error) {
	if identity.Subject != client.config.Subject || identity.Actor != "telegram-agent" || identity.Channel != "telegram" {
		return nil, errors.New("trusted Telegram identity does not match gateway credentials")
	}
	token, err := (oidcclient.Client{
		Endpoint:     client.config.TokenEndpoint,
		ClientID:     client.config.ClientID,
		ClientSecret: client.config.ClientSecret,
		HTTPClient:   client.config.HTTPClient,
	}).PasswordToken(ctx, client.config.Username, client.config.Password)
	if err != nil {
		return nil, err
	}
	baseTransport := http.DefaultTransport
	if client.config.HTTPClient != nil && client.config.HTTPClient.Transport != nil {
		baseTransport = client.config.HTTPClient.Transport
	}
	authorizedClient := &http.Client{Transport: &oauth2.Transport{
		Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
		Base:   baseTransport,
	}}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "telegram-adapter", Version: "v0.3.0"}, nil)
	session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             client.config.Endpoint,
		DisableStandaloneSSE: true,
		HTTPClient:           authorizedClient,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect Telegram Actor to gateway: %w", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "calendar.find_availability",
		Arguments: map[string]any{
			"start": query.Start.Format("2006-01-02T15:04:05Z07:00"),
			"end":   query.End.Format("2006-01-02T15:04:05Z07:00"),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("call availability Tool: %w", err)
	}
	if result.IsError {
		return nil, result.GetError()
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return nil, fmt.Errorf("encode Free/Busy View: %w", err)
	}
	var view struct {
		AvailableIntervals []AvailableInterval `json:"available_intervals"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil {
		return nil, fmt.Errorf("decode Free/Busy View: %w", err)
	}
	return view.AvailableIntervals, nil
}
