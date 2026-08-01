package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

func (client Client) PasswordToken(ctx context.Context, username, password string) (string, error) {
	return client.PasswordTokenWithScopes(ctx, username, password, nil)
}

func (client Client) PasswordTokenWithScopes(ctx context.Context, username, password string, scopes []string) (string, error) {
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"username":      {username},
		"password":      {password},
	}
	if len(scopes) > 0 {
		form.Set("scope", "openid "+strings.Join(scopes, " "))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create identity token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request identity token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("identity provider returned HTTP %d", response.StatusCode)
	}
	var document struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil || document.AccessToken == "" {
		return "", errors.New("identity provider returned no access token")
	}
	return document.AccessToken, nil
}
