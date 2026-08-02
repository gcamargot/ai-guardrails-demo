package oidcauth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
	"github.com/nahtao97/agent-tool-guardrails/internal/oidcauth"
)

func TestSignedOIDCTokenProducesTrustedIdentity(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)
	authenticator, err := oidcauth.New(t.Context(), oidcauth.Config{
		Issuer:          issuer.URL,
		Audience:        "agent-tools-gateway",
		RequiredScopes:  []gateway.Capability{"coffee_station.read"},
		DiscoveryClient: issuer.Client(),
	})
	if err != nil {
		t.Fatalf("create OIDC authenticator: %v", err)
	}

	token := issuer.sign(t, map[string]any{
		"iss":   issuer.URL,
		"sub":   "owner-subject-id",
		"aud":   "agent-tools-gateway",
		"azp":   "coding-agent",
		"exp":   time.Now().Add(time.Minute).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"scope": "openid coffee_station.read smart_lock.write",
	})
	identity, err := authenticator.Verify(t.Context(), token)
	if err != nil {
		t.Fatalf("verify signed token: %v", err)
	}

	want := gateway.TrustedIdentity{
		Subject:          "owner-subject-id",
		Actor:            "coding-agent",
		TurnCapabilities: []gateway.Capability{"coffee_station.read"},
	}
	if identity.Subject != want.Subject || identity.Actor != want.Actor ||
		len(identity.TurnCapabilities) != 1 || identity.TurnCapabilities[0] != want.TurnCapabilities[0] {
		t.Fatalf("trusted identity = %#v, want %#v", identity, want)
	}
}

func TestExplicitOptionalScopeBecomesTurnCapability(t *testing.T) {
	t.Parallel()
	issuer := newTestIssuer(t)
	authenticator, err := oidcauth.New(t.Context(), oidcauth.Config{
		Issuer: issuer.URL, Audience: "agent-tools-gateway",
		RequiredScopes: []gateway.Capability{"calendar.meeting.propose"},
		OptionalScopes: []gateway.Capability{"calendar.meeting.approve"}, DiscoveryClient: issuer.Client(),
	})
	if err != nil {
		t.Fatalf("create OIDC authenticator: %v", err)
	}
	claims := validClaims(issuer.URL)
	claims["scope"] = "calendar.meeting.propose calendar.meeting.approve"
	identity, err := authenticator.Verify(t.Context(), issuer.sign(t, claims))
	if err != nil {
		t.Fatalf("verify explicit approval token: %v", err)
	}
	if len(identity.TurnCapabilities) != 2 || identity.TurnCapabilities[1] != "calendar.meeting.approve" {
		t.Fatalf("Turn Capabilities = %#v", identity.TurnCapabilities)
	}
}

func TestTwoOAuthClientsRemainDistinctActorsForSameSubject(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)
	authenticator, err := oidcauth.New(t.Context(), oidcauth.Config{
		Issuer:          issuer.URL,
		Audience:        "agent-tools-gateway",
		RequiredScopes:  []gateway.Capability{"coffee_station.read"},
		DiscoveryClient: issuer.Client(),
	})
	if err != nil {
		t.Fatalf("create OIDC authenticator: %v", err)
	}

	actors := []gateway.Actor{"telegram-agent", "coding-agent"}
	for _, actor := range actors {
		claims := validClaims(issuer.URL)
		claims["azp"] = string(actor)
		identity, err := authenticator.Verify(t.Context(), issuer.sign(t, claims))
		if err != nil {
			t.Fatalf("verify %s token: %v", actor, err)
		}
		if identity.Subject != "owner-subject-id" || identity.Actor != actor {
			t.Errorf("identity for %s = %#v", actor, identity)
		}
	}
}

func TestVerifierCanUseInternalJWKSWithoutWeakeningExternalIssuerValidation(t *testing.T) {
	t.Parallel()
	keys := newTestIssuer(t)
	authenticator, err := oidcauth.New(t.Context(), oidcauth.Config{
		Issuer: "http://127.0.0.1:8082/realms/agent-tools", Audience: "agent-tools-gateway",
		JWKSURL: keys.URL + "/keys", RequiredScopes: []gateway.Capability{"dev.repository.read"},
	})
	if err != nil {
		t.Fatalf("create split-path verifier: %v", err)
	}
	claims := validClaims("http://127.0.0.1:8082/realms/agent-tools")
	claims["scope"] = "openid dev.repository.read"
	identity, err := authenticator.Verify(t.Context(), keys.sign(t, claims))
	if err != nil || identity.Subject != "owner-subject-id" || identity.Actor != "coding-agent" {
		t.Fatalf("verify externally-issued token from internal JWKS: identity=%#v err=%v", identity, err)
	}
	wrongIssuer := validClaims("http://keycloak:8080/realms/agent-tools")
	wrongIssuer["scope"] = "openid dev.repository.read"
	if _, err := authenticator.Verify(t.Context(), keys.sign(t, wrongIssuer)); err == nil {
		t.Fatal("internal transport location was accepted as token issuer")
	}
}

func TestAuthenticatorHealthFailsWhenIdentityControlPlaneIsUnavailable(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator, err := oidcauth.New(t.Context(), oidcauth.Config{
		Issuer: issuer.URL, Audience: "agent-tools-gateway", JWKSURL: issuer.URL + "/keys",
		RequiredScopes: []gateway.Capability{"coffee_station.read"}, DiscoveryClient: issuer.Client(),
	})
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}
	if err := authenticator.Health(t.Context()); err != nil {
		t.Fatalf("healthy identity control plane: %v", err)
	}
	issuer.Close()
	if err := authenticator.Health(t.Context()); err == nil {
		t.Fatal("unavailable identity control plane reported healthy")
	}
}

func TestInvalidOIDCTokensFailClosed(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)
	authenticator, err := oidcauth.New(t.Context(), oidcauth.Config{
		Issuer:          issuer.URL,
		Audience:        "agent-tools-gateway",
		RequiredScopes:  []gateway.Capability{"coffee_station.read"},
		DiscoveryClient: issuer.Client(),
	})
	if err != nil {
		t.Fatalf("create OIDC authenticator: %v", err)
	}

	tests := map[string]func() string{
		"malformed": func() string { return "not-a-jwt" },
		"wrong issuer": func() string {
			claims := validClaims(issuer.URL)
			claims["iss"] = "https://attacker.invalid"
			return issuer.sign(t, claims)
		},
		"wrong audience": func() string {
			claims := validClaims(issuer.URL)
			claims["aud"] = "another-service"
			return issuer.sign(t, claims)
		},
		"expired": func() string {
			claims := validClaims(issuer.URL)
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
			return issuer.sign(t, claims)
		},
		"missing required scope": func() string {
			claims := validClaims(issuer.URL)
			claims["scope"] = "openid profile"
			return issuer.sign(t, claims)
		},
		"missing subject": func() string {
			claims := validClaims(issuer.URL)
			delete(claims, "sub")
			return issuer.sign(t, claims)
		},
		"missing actor": func() string {
			claims := validClaims(issuer.URL)
			delete(claims, "azp")
			return issuer.sign(t, claims)
		},
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := authenticator.Verify(t.Context(), token()); err == nil {
				t.Fatal("invalid token was accepted")
			}
		})
	}
}

func validClaims(issuer string) map[string]any {
	return map[string]any{
		"iss":   issuer,
		"sub":   "owner-subject-id",
		"aud":   "agent-tools-gateway",
		"azp":   "coding-agent",
		"exp":   time.Now().Add(time.Minute).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"scope": "openid coffee_station.read",
	}
}

type testIssuer struct {
	*httptest.Server
	privateKey *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	issuer := &testIssuer{privateKey: privateKey}
	issuer.Server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"issuer":                                issuer.URL,
				"authorization_endpoint":                issuer.URL + "/authorize",
				"token_endpoint":                        issuer.URL + "/token",
				"jwks_uri":                              issuer.URL + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "RSA",
				"kid": "demo-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(issuer.Close)
	return issuer
}

func (issuer *testIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := encodeJSON(t, map[string]any{"alg": "RS256", "kid": "demo-key", "typ": "JWT"})
	payload := encodeJSON(t, claims)
	unsigned := header + "." + payload
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, issuer.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode JWT segment: %v", err)
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
