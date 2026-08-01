package outlookclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nahtao97/agent-tool-guardrails/internal/outlook"
)

const maxResponseBytes = 1 << 20

type Client struct {
	baseURL    string
	credential string
	httpClient *http.Client
}

func New(baseURL, credential string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), credential: credential, httpClient: httpClient}
}

func (client *Client) SearchMessages(ctx context.Context, query outlook.SearchQuery) ([]outlook.SearchResult, error) {
	values := url.Values{"query": {string(query.Query)}, "limit": {strconv.Itoa(query.Limit)}}
	request, err := client.request(ctx, client.baseURL+"/messages/search?"+values.Encode())
	if err != nil {
		return nil, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("search Outlook: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Outlook search returned HTTP %d", response.StatusCode)
	}
	var view struct {
		Messages []outlook.SearchResult `json:"messages"`
	}
	if err := decode(response, &view); err != nil {
		return nil, fmt.Errorf("decode minimized Outlook search: %w", err)
	}
	return view.Messages, nil
}

func (client *Client) ReadMessage(ctx context.Context, messageID outlook.MessageID) (outlook.MessageView, error) {
	request, err := client.request(ctx, client.baseURL+"/messages/"+url.PathEscape(string(messageID)))
	if err != nil {
		return outlook.MessageView{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return outlook.MessageView{}, fmt.Errorf("read Outlook message: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return outlook.MessageView{}, fmt.Errorf("Outlook read returned HTTP %d", response.StatusCode)
	}
	var view outlook.MessageView
	if err := decode(response, &view); err != nil {
		return outlook.MessageView{}, fmt.Errorf("decode minimized Outlook Message View: %w", err)
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
		return fmt.Errorf("Outlook health returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (client *Client) request(ctx context.Context, endpoint string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create Outlook request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.credential)
	return request, nil
}

func decode(response *http.Response, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}
