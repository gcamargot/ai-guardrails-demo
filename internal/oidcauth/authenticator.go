package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

type Config struct {
	Issuer          string
	Audience        string
	RequiredScopes  []gateway.Capability
	OptionalScopes  []gateway.Capability
	DiscoveryClient *http.Client
	JWKSURL         string
}

type Authenticator struct {
	verifier       *oidc.IDTokenVerifier
	requiredScopes []gateway.Capability
	optionalScopes []gateway.Capability
	healthURL      string
	httpClient     *http.Client
}

func New(ctx context.Context, config Config) (*Authenticator, error) {
	if config.Issuer == "" || config.Audience == "" || len(config.RequiredScopes) == 0 {
		return nil, errors.New("OIDC issuer, audience and required scopes are required")
	}
	if config.DiscoveryClient != nil {
		ctx = oidc.ClientContext(ctx, config.DiscoveryClient)
	}
	var verifier *oidc.IDTokenVerifier
	if config.JWKSURL != "" {
		verifier = oidc.NewVerifier(config.Issuer, oidc.NewRemoteKeySet(ctx, config.JWKSURL), &oidc.Config{ClientID: config.Audience})
	} else {
		provider, err := oidc.NewProvider(ctx, config.Issuer)
		if err != nil {
			return nil, fmt.Errorf("discover OIDC issuer: %w", err)
		}
		verifier = provider.Verifier(&oidc.Config{ClientID: config.Audience})
	}
	return &Authenticator{
		verifier:       verifier,
		requiredScopes: append([]gateway.Capability(nil), config.RequiredScopes...),
		optionalScopes: append([]gateway.Capability(nil), config.OptionalScopes...),
		healthURL:      identityHealthURL(config),
		httpClient:     identityHTTPClient(config.DiscoveryClient),
	}, nil
}

func identityHealthURL(config Config) string {
	if config.JWKSURL != "" {
		return config.JWKSURL
	}
	return strings.TrimRight(config.Issuer, "/") + "/.well-known/openid-configuration"
}

func identityHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}

func (authenticator *Authenticator) Health(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, authenticator.healthURL, nil)
	if err != nil {
		return fmt.Errorf("create identity health request: %w", err)
	}
	response, err := authenticator.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("query identity control plane: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("identity control plane returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (authenticator *Authenticator) Verify(ctx context.Context, rawToken string) (gateway.TrustedIdentity, error) {
	token, err := authenticator.verifier.Verify(ctx, rawToken)
	if err != nil {
		return gateway.TrustedIdentity{}, fmt.Errorf("verify OIDC token: %w", err)
	}
	var claims struct {
		Subject string `json:"sub"`
		Actor   string `json:"azp"`
		Scope   string `json:"scope"`
	}
	if err := token.Claims(&claims); err != nil {
		return gateway.TrustedIdentity{}, fmt.Errorf("decode trusted claims: %w", err)
	}
	if claims.Subject == "" || claims.Actor == "" {
		return gateway.TrustedIdentity{}, errors.New("OIDC subject and actor claims are required")
	}

	granted := make(map[string]struct{}, len(strings.Fields(claims.Scope)))
	for _, scope := range strings.Fields(claims.Scope) {
		granted[scope] = struct{}{}
	}
	capabilities := make([]gateway.Capability, 0, len(authenticator.requiredScopes))
	for _, required := range authenticator.requiredScopes {
		if _, ok := granted[string(required)]; !ok {
			return gateway.TrustedIdentity{}, fmt.Errorf("required scope %q is missing", required)
		}
		capabilities = append(capabilities, required)
	}
	for _, optional := range authenticator.optionalScopes {
		if _, ok := granted[string(optional)]; ok {
			capabilities = append(capabilities, optional)
		}
	}
	return gateway.TrustedIdentity{
		Subject:          gateway.Subject(claims.Subject),
		Actor:            gateway.Actor(claims.Actor),
		TurnCapabilities: capabilities,
	}, nil
}
