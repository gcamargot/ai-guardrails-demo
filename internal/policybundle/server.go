package policybundle

import (
	"net/http"
	"os"
	"sync"
)

type Config struct {
	ValidPath   string
	InvalidPath string
}

type server struct {
	config  Config
	mu      sync.RWMutex
	invalid bool
}

func NewHandler(config Config) http.Handler {
	service := &server{config: config}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", service.health)
	mux.HandleFunc("GET /bundles/agent-tools.tar.gz", service.bundle)
	mux.HandleFunc("POST /updates/invalid-signature", service.publishInvalid)
	return mux
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
	etag := `"ticket-08"`
	if invalid {
		path = service.config.InvalidPath
		etag = `"ticket-08-untrusted-update"`
	}
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
