package vaultclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func ReadToken(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Vault token file: %w", err)
	}
	token := strings.TrimSpace(string(content))
	if token == "" {
		return "", errors.New("Vault token file is empty")
	}
	return token, nil
}

func New(baseURL, token string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, httpClient: httpClient}
}

func (client *Client) CalendarCredential(ctx context.Context) (string, error) {
	return client.credential(ctx, "calendar")
}

func (client *Client) OutlookCredential(ctx context.Context) (string, error) {
	return client.credential(ctx, "outlook")
}

func (client *Client) SmartLockCredential(ctx context.Context) (string, error) {
	return client.credential(ctx, "smart-lock")
}

func (client *Client) DemoResetCredential(ctx context.Context) (string, error) {
	return client.credential(ctx, "demo-reset")
}

func (client *Client) credential(ctx context.Context, resource string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/v1/secret/data/"+resource, nil)
	if err != nil {
		return "", fmt.Errorf("create Vault request: %w", err)
	}
	request.Header.Set("X-Vault-Token", client.token)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("read %s credential from Vault: %w", resource, err)
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
		return "", fmt.Errorf("Vault %s credential is missing", resource)
	}
	return document.Data.Data.Credential, nil
}
