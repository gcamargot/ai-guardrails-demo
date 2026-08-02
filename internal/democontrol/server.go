package democontrol

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nahtao97/agent-tool-guardrails/internal/smartlock"
)

type Config struct {
	Credential      string
	InsecureLockURL string
	SecureLockURL   string
	AuditURL        string
	ApprovalURL     string
	HTTPClient      *http.Client
}

type lockEvidence struct {
	State       smartlock.StateName `json:"state"`
	UnlockCount int                 `json:"unlock_count"`
}

type resetEvidence struct {
	AuditRecordCount     int `json:"audit_record_count"`
	ApprovalConsumeCount int `json:"approval_consume_count"`
}

type resetResult struct {
	ScenarioState string        `json:"scenario_state"`
	InsecureLock  lockEvidence  `json:"insecure_lock"`
	SecureLock    lockEvidence  `json:"secure_lock"`
	Evidence      resetEvidence `json:"evidence"`
}

func NewHandler(config Config) http.Handler {
	if config.HTTPClient == nil {
		config.HTTPClient = http.DefaultClient
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("POST /demo/reset", func(response http.ResponseWriter, request *http.Request) {
		want := "Bearer " + config.Credential
		if config.Credential == "" || !hmac.Equal([]byte(request.Header.Get("Authorization")), []byte(want)) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		result, err := reset(request, config)
		if err != nil {
			http.Error(response, "demo reset unavailable", http.StatusBadGateway)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(result)
	})
	return mux
}

func reset(request *http.Request, config Config) (resetResult, error) {
	targets := []struct {
		baseURL string
		path    string
	}{
		{trimURL(config.InsecureLockURL), "/test/reset"},
		{trimURL(config.SecureLockURL), "/test/reset"},
		{trimURL(config.AuditURL), "/test/reset"},
		{trimURL(config.ApprovalURL), "/test/reset-metrics"},
	}
	for _, target := range targets {
		if err := postReset(request, config.HTTPClient, target.baseURL+target.path, config.Credential); err != nil {
			return resetResult{}, err
		}
	}
	insecure, err := readJSON[lockEvidence](request, config.HTTPClient, trimURL(config.InsecureLockURL)+"/metrics")
	if err != nil {
		return resetResult{}, err
	}
	secure, err := readJSON[lockEvidence](request, config.HTTPClient, trimURL(config.SecureLockURL)+"/metrics")
	if err != nil {
		return resetResult{}, err
	}
	records, err := readJSON[[]json.RawMessage](request, config.HTTPClient, trimURL(config.AuditURL)+"/records")
	if err != nil {
		return resetResult{}, err
	}
	approvals, err := readJSON[struct {
		ConsumeCount int `json:"consume_count"`
	}](request, config.HTTPClient, trimURL(config.ApprovalURL)+"/metrics")
	if err != nil {
		return resetResult{}, err
	}
	return resetResult{
		ScenarioState: "ready", InsecureLock: insecure, SecureLock: secure,
		Evidence: resetEvidence{AuditRecordCount: len(records), ApprovalConsumeCount: approvals.ConsumeCount},
	}, nil
}

func postReset(parent *http.Request, client *http.Client, endpoint, credential string) error {
	request, err := http.NewRequestWithContext(parent.Context(), http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("reset target returned HTTP %d", response.StatusCode)
	}
	return nil
}

func readJSON[T any](parent *http.Request, client *http.Client, endpoint string) (T, error) {
	var value T
	request, err := http.NewRequestWithContext(parent.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		return value, err
	}
	response, err := client.Do(request)
	if err != nil {
		return value, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return value, fmt.Errorf("reset evidence returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return value, errors.New("multiple JSON values")
	}
	return value, nil
}

func trimURL(value string) string { return strings.TrimRight(value, "/") }
