package policybundle_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nahtao97/agent-tool-guardrails/internal/policybundle"
)

func TestBundleServicePublishesAnInvalidUpdateWithoutReplacingItsLastGoodArtifact(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid.tar.gz")
	invalidPath := filepath.Join(directory, "invalid.tar.gz")
	if err := os.WriteFile(validPath, []byte("signed-ticket-08"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidPath, []byte("untrusted-update"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(policybundle.NewHandler(policybundle.Config{
		ValidPath: validPath, InvalidPath: invalidPath,
	}))
	t.Cleanup(server.Close)

	assertBundle(t, server.URL, `"ticket-08"`, "signed-ticket-08")

	request, err := http.NewRequest(http.MethodPost, server.URL+"/updates/invalid-signature", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("publish invalid status = %d, want 204", response.StatusCode)
	}

	assertBundle(t, server.URL, `"ticket-08-untrusted-update"`, "untrusted-update")
}

func assertBundle(t *testing.T, baseURL, wantETag, wantBody string) {
	t.Helper()
	response, err := http.Get(baseURL + "/bundles/agent-tools.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("ETag") != wantETag || string(body) != wantBody {
		t.Fatalf("bundle response = status %d etag %q body %q", response.StatusCode, response.Header.Get("ETag"), body)
	}
}
