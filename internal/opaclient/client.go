package opaclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

const maxResponseBytes = 1 << 20

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

func (client *Client) Decide(ctx context.Context, input gateway.PolicyInput) (gateway.PolicyDecision, error) {
	body, err := json.Marshal(struct {
		Input gateway.PolicyInput `json:"input"`
	}{Input: input})
	if err != nil {
		return gateway.PolicyDecision{}, fmt.Errorf("encode OPA input: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		client.baseURL+"/v1/data/agent_tools/decision",
		strings.NewReader(string(body)),
	)
	if err != nil {
		return gateway.PolicyDecision{}, fmt.Errorf("create OPA request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return gateway.PolicyDecision{}, fmt.Errorf("query OPA: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return gateway.PolicyDecision{}, fmt.Errorf("OPA decision returned HTTP %d", response.StatusCode)
	}

	var document struct {
		DecisionID string `json:"decision_id"`
		Result     *struct {
			Allow          bool                  `json:"allow"`
			CorrelationID  gateway.CorrelationID `json:"correlation_id"`
			Obligations    []gateway.Obligation  `json:"obligations"`
			PolicyRevision string                `json:"policy_revision"`
			Reason         string                `json:"reason"`
		} `json:"result"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if err := decoder.Decode(&document); err != nil {
		return gateway.PolicyDecision{}, fmt.Errorf("decode OPA decision: %w", err)
	}
	if document.Result == nil {
		return gateway.PolicyDecision{}, errors.New("OPA decision is undefined")
	}
	if document.DecisionID == "" {
		return gateway.PolicyDecision{}, errors.New("OPA decision_id is missing")
	}
	if document.Result.CorrelationID == "" {
		return gateway.PolicyDecision{}, errors.New("OPA correlation_id is missing")
	}
	if document.Result.CorrelationID != input.CorrelationID {
		return gateway.PolicyDecision{}, errors.New("OPA correlation_id does not match policy input")
	}
	if document.Result.PolicyRevision == "" {
		return gateway.PolicyDecision{}, errors.New("OPA policy_revision is missing")
	}
	return gateway.PolicyDecision{
		Allow:          document.Result.Allow,
		CorrelationID:  document.Result.CorrelationID,
		DecisionID:     document.DecisionID,
		Obligations:    document.Result.Obligations,
		PolicyRevision: document.Result.PolicyRevision,
		Reason:         document.Result.Reason,
	}, nil
}

func (client *Client) Health(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("create OPA health request: %w", err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("query OPA health: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("OPA health returned HTTP %d", response.StatusCode)
	}
	return nil
}
