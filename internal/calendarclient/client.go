package calendarclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nahtao97/agent-tool-guardrails/internal/freebusy"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
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

func (client *Client) FindAvailability(ctx context.Context, query freebusy.Window) (freebusy.View, error) {
	values := url.Values{
		"start": {query.Start.Format("2006-01-02T15:04:05Z07:00")},
		"end":   {query.End.Format("2006-01-02T15:04:05Z07:00")},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/free-busy?"+values.Encode(), nil)
	if err != nil {
		return freebusy.View{}, fmt.Errorf("create calendar request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.credential)
	gateway.ApplyToolCallCorrelation(ctx, request)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return freebusy.View{}, fmt.Errorf("query calendar: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return freebusy.View{}, fmt.Errorf("calendar returned HTTP %d", response.StatusCode)
	}
	var view freebusy.View
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil {
		return freebusy.View{}, fmt.Errorf("decode minimized Free/Busy View: %w", err)
	}
	return view, nil
}

func (client *Client) CreateEvent(ctx context.Context, arguments meeting.EventArguments) (meeting.Event, error) {
	body, err := json.Marshal(arguments)
	if err != nil {
		return meeting.Event{}, fmt.Errorf("encode calendar event: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+"/events", bytes.NewReader(body))
	if err != nil {
		return meeting.Event{}, fmt.Errorf("create calendar event request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.credential)
	request.Header.Set("Content-Type", "application/json")
	gateway.ApplyToolCallCorrelation(ctx, request)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return meeting.Event{}, fmt.Errorf("create calendar event: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return meeting.Event{}, fmt.Errorf("calendar event returned HTTP %d", response.StatusCode)
	}
	var event meeting.Event
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return meeting.Event{}, fmt.Errorf("decode calendar event: %w", err)
	}
	return event, nil
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
