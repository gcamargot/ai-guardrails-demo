package policybundle

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

type Config struct {
	ValidPath   string
	InvalidPath string
}

type server struct {
	config          Config
	validRevision   string
	invalidRevision string
	mu              sync.RWMutex
	invalid         bool
}

func NewHandler(config Config) (http.Handler, error) {
	validRevision, err := bundleRevision(config.ValidPath)
	if err != nil {
		return nil, fmt.Errorf("read valid bundle revision: %w", err)
	}
	invalidRevision, err := bundleRevision(config.InvalidPath)
	if err != nil {
		return nil, fmt.Errorf("read invalid bundle revision: %w", err)
	}
	service := &server{config: config, validRevision: validRevision, invalidRevision: invalidRevision}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", service.health)
	mux.HandleFunc("GET /bundles/agent-tools.tar.gz", service.bundle)
	mux.HandleFunc("POST /updates/invalid-signature", service.publishInvalid)
	mux.HandleFunc("POST /updates/valid", service.publishValid)
	return mux, nil
}

func (service *server) health(response http.ResponseWriter, _ *http.Request) {
	if _, err := os.Stat(service.config.ValidPath); err != nil {
		http.Error(response, "bundle unavailable", http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusOK)
}

func (service *server) bundle(response http.ResponseWriter, request *http.Request) {
	service.mu.RLock()
	invalid := service.invalid
	service.mu.RUnlock()

	path := service.config.ValidPath
	revision := service.validRevision
	if invalid {
		path = service.config.InvalidPath
		revision = service.invalidRevision
	}
	etag := `"` + revision + `"`
	if request.Header.Get("If-None-Match") == etag {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	bundle, err := os.ReadFile(path)
	if err != nil {
		http.Error(response, "bundle unavailable", http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", "application/gzip")
	response.Header().Set("ETag", etag)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(bundle)
}

func bundleRevision(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("open gzip: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			return "", errors.New("bundle manifest is missing")
		}
		if nextErr != nil {
			return "", fmt.Errorf("read archive: %w", nextErr)
		}
		if strings.TrimPrefix(header.Name, "/") != ".manifest" {
			continue
		}
		var manifest struct {
			Revision string `json:"revision"`
		}
		if err := json.NewDecoder(io.LimitReader(tarReader, 1<<20)).Decode(&manifest); err != nil {
			return "", fmt.Errorf("decode manifest: %w", err)
		}
		if manifest.Revision == "" || strings.ContainsAny(manifest.Revision, "\"\r\n") {
			return "", errors.New("bundle revision is invalid")
		}
		return manifest.Revision, nil
	}
}

func (service *server) publishInvalid(response http.ResponseWriter, _ *http.Request) {
	if _, err := os.Stat(service.config.InvalidPath); err != nil {
		http.Error(response, "invalid update fixture unavailable", http.StatusServiceUnavailable)
		return
	}
	service.mu.Lock()
	service.invalid = true
	service.mu.Unlock()
	response.WriteHeader(http.StatusNoContent)
}

func (service *server) publishValid(response http.ResponseWriter, _ *http.Request) {
	if _, err := os.Stat(service.config.ValidPath); err != nil {
		http.Error(response, "valid bundle unavailable", http.StatusServiceUnavailable)
		return
	}
	service.mu.Lock()
	service.invalid = false
	service.mu.Unlock()
	response.WriteHeader(http.StatusNoContent)
}
