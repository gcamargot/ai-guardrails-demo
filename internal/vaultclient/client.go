package vaultclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func New(baseURL, token string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, httpClient: httpClient}
}

func (client *Client) CalendarCredential(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/v1/secret/data/calendar", nil)
	if err != nil {
		return "", fmt.Errorf("create Vault request: %w", err)
	}
	request.Header.Set("X-Vault-Token", client.token)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("read calendar credential from Vault: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Vault returned HTTP %d", response.StatusCode)
	}
	var document struct {
		Data struct {
			Data struct {
				Credential string `json:"credential"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return "", fmt.Errorf("decode Vault secret: %w", err)
	}
	if document.Data.Data.Credential == "" {
		return "", errors.New("Vault calendar credential is missing")
	}
	return document.Data.Data.Credential, nil
}
