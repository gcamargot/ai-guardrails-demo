package oauthfacade

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

func NewHandler(backend string) http.Handler {
	target, err := url.Parse(backend)
	if err != nil {
		panic(fmt.Sprintf("invalid OAuth backend URL: %v", err))
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(response *http.Response) error {
		path := response.Request.URL.Path
		isMetadata := strings.HasSuffix(path, "/.well-known/openid-configuration") ||
			strings.Contains(path, "/.well-known/oauth-authorization-server")
		if !isMetadata || response.StatusCode != http.StatusOK {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if err != nil {
			return fmt.Errorf("read authorization metadata: %w", err)
		}
		var metadata map[string]any
		if err := json.Unmarshal(body, &metadata); err != nil {
			return fmt.Errorf("decode authorization metadata: %w", err)
		}
		metadata["authorization_response_iss_parameter_supported"] = false
		body, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("encode authorization metadata: %w", err)
		}
		response.Body = io.NopCloser(bytes.NewReader(body))
		response.ContentLength = int64(len(body))
		response.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	mux := http.NewServeMux()
	var identityUnavailable atomic.Bool
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("POST /test/identity/unavailable", func(response http.ResponseWriter, _ *http.Request) {
		identityUnavailable.Store(true)
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /test/identity/available", func(response http.ResponseWriter, _ *http.Request) {
		identityUnavailable.Store(false)
		response.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if identityUnavailable.Load() && strings.HasSuffix(request.URL.Path, "/protocol/openid-connect/certs") {
			http.Error(response, "identity unavailable", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(response, request)
	}))
	return mux
}
