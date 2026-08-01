package approvalauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type Client struct {
	baseURL    string
	credential string
	httpClient *http.Client
}

type Consumption struct {
	TraceID string
}

func NewClient(baseURL, credential string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), credential: credential, httpClient: httpClient}
}

func (client *Client) Issue(ctx context.Context, binding Binding) (string, error) {
	response, err := client.post(ctx, "/approvals/issue", map[string]any{"binding": binding})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("Approval Authority issue returned HTTP %d", response.StatusCode)
	}
	var output struct {
		Approval string `json:"approval"`
	}
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&output) != nil || output.Approval == "" {
		return "", errors.New("Approval Authority returned malformed Approval")
	}
	return output.Approval, nil
}

func (client *Client) Consume(ctx context.Context, approval string, binding Binding) error {
	_, err := client.ConsumeExact(ctx, approval, binding)
	return err
}

func (client *Client) ConsumeExact(ctx context.Context, approval string, binding Binding) (Consumption, error) {
	response, err := client.post(ctx, "/approvals/consume", map[string]any{"approval": approval, "binding": binding})
	if err != nil {
		return Consumption{}, err
	}
	defer response.Body.Close()
	consumed := Consumption{TraceID: response.Header.Get("X-Approval-Trace-ID")}
	if response.StatusCode != http.StatusNoContent {
		return consumed, fmt.Errorf("Approval denied with HTTP %d", response.StatusCode)
	}
	if consumed.TraceID == "" {
		return Consumption{}, errors.New("Approval Authority returned no trace correlation")
	}
	return consumed, nil
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
		return fmt.Errorf("Approval Authority health returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (client *Client) post(ctx context.Context, path string, value any) (*http.Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.credential)
	return client.httpClient.Do(request)
}
