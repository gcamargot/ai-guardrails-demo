package calendarclient

import (
	"context"
	"encoding/json"
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
	credential string
	httpClient *http.Client
}

func New(baseURL, credential string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		credential: credential,
		httpClient: httpClient,
	}
}

func (client *Client) FindAvailability(ctx context.Context, query gateway.AvailabilityQuery) (gateway.FreeBusyView, error) {
	values := url.Values{
		"start": {query.Start.Format("2006-01-02T15:04:05Z07:00")},
		"end":   {query.End.Format("2006-01-02T15:04:05Z07:00")},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/free-busy?"+values.Encode(), nil)
	if err != nil {
		return gateway.FreeBusyView{}, fmt.Errorf("create calendar request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.credential)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return gateway.FreeBusyView{}, fmt.Errorf("query calendar: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return gateway.FreeBusyView{}, fmt.Errorf("calendar returned HTTP %d", response.StatusCode)
	}
	var view gateway.FreeBusyView
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil {
		return gateway.FreeBusyView{}, fmt.Errorf("decode minimized Free/Busy View: %w", err)
	}
	return view, nil
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
		return fmt.Errorf("calendar health returned HTTP %d", response.StatusCode)
	}
	return nil
}
