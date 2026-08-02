package developmentclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nahtao97/agent-tool-guardrails/internal/development"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient}
}

func (client *Client) Read(ctx context.Context, path development.RepositoryPath) (development.RepositoryDocument, error) {
	endpoint := client.baseURL + "/repository?path=" + url.QueryEscape(string(path))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return development.RepositoryDocument{}, fmt.Errorf("create repository read: %w", err)
	}
	gateway.ApplyToolCallCorrelation(ctx, request)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return development.RepositoryDocument{}, fmt.Errorf("read repository: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return development.RepositoryDocument{}, fmt.Errorf("repository returned HTTP %d", response.StatusCode)
	}
	var document development.RepositoryDocument
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return development.RepositoryDocument{}, fmt.Errorf("decode repository document: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return development.RepositoryDocument{}, fmt.Errorf("decode repository document: trailing data")
	}
	return document, nil
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
		return fmt.Errorf("repository health returned HTTP %d", response.StatusCode)
	}
	return nil
}
