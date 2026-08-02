package policybundle_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	validBundle := writeBundle(t, validPath, "ticket-08")
	invalidBundle := writeBundle(t, invalidPath, "review-42-untrusted-update")

	handler, err := policybundle.NewHandler(policybundle.Config{
		ValidPath: validPath, InvalidPath: invalidPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	assertBundle(t, server.URL, `"ticket-08"`, validBundle)

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

	assertBundle(t, server.URL, `"review-42-untrusted-update"`, invalidBundle)

	request, err = http.NewRequest(http.MethodPost, server.URL+"/updates/valid", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("restore valid status = %d, want 204", response.StatusCode)
	}
	assertBundle(t, server.URL, `"ticket-08"`, validBundle)
}

func assertBundle(t *testing.T, baseURL, wantETag string, wantBody []byte) {
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
	if response.StatusCode != http.StatusOK || response.Header.Get("ETag") != wantETag || !bytes.Equal(body, wantBody) {
		t.Fatalf("bundle response = status %d etag %q body %q", response.StatusCode, response.Header.Get("ETag"), body)
	}
}

func writeBundle(t *testing.T, path, revision string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	manifest := []byte(`{"revision":"` + revision + `"}`)
	if err := tarWriter.WriteHeader(&tar.Header{Name: ".manifest", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
