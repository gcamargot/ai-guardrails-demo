package coffeestationclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func (client *Client) Status(ctx context.Context, stationID gateway.StationID) (gateway.CoffeeStationStatus, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		client.baseURL+"/stations/"+url.PathEscape(string(stationID))+"/status",
		nil,
	)
	if err != nil {
		return gateway.CoffeeStationStatus{}, fmt.Errorf("create coffee station request: %w", err)
	}
	gateway.ApplyToolCallCorrelation(ctx, request)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return gateway.CoffeeStationStatus{}, fmt.Errorf("query coffee station: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return gateway.CoffeeStationStatus{}, fmt.Errorf("coffee station returned HTTP %d", response.StatusCode)
	}

	var status gateway.CoffeeStationStatus
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return gateway.CoffeeStationStatus{}, fmt.Errorf("decode coffee station response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return gateway.CoffeeStationStatus{}, errors.New("coffee station returned multiple JSON values")
	}
	return status, nil
}

func (client *Client) Health(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("create coffee station health request: %w", err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("query coffee station health: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("coffee station health returned HTTP %d", response.StatusCode)
	}
	return nil
}
