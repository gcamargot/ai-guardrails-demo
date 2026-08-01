package smartlockclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nahtao97/agent-tool-guardrails/internal/smartlock"
)

type Client struct {
	baseURL    string
	credential string
	httpClient *http.Client
}

func New(baseURL, credential string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), credential: credential, httpClient: httpClient}
}

func (client *Client) Unlock(ctx context.Context, deviceID smartlock.DeviceID) (smartlock.State, error) {
	body, err := json.Marshal(smartlock.Arguments{DeviceID: deviceID})
	if err != nil {
		return smartlock.State{}, fmt.Errorf("encode smart-lock request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+"/unlock", bytes.NewReader(body))
	if err != nil {
		return smartlock.State{}, fmt.Errorf("create smart-lock request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return smartlock.State{}, fmt.Errorf("unlock smart lock: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return smartlock.State{}, fmt.Errorf("smart-lock adapter returned HTTP %d", response.StatusCode)
	}
	var state smartlock.State
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || decoder.Decode(&struct{}{}) != io.EOF || state.DeviceID != deviceID || state.State != smartlock.StateUnlocked {
		return smartlock.State{}, fmt.Errorf("smart-lock adapter returned invalid state")
	}
	return state, nil
}

func (client *Client) Health(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("smart-lock health returned HTTP %d", response.StatusCode)
	}
	return nil
}
