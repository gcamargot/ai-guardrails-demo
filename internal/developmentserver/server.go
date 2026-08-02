package developmentserver

import (
	"encoding/json"
	"net/http"

	"github.com/nahtao97/agent-tool-guardrails/internal/development"
)

func NewHandler(content string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("GET /repository", func(response http.ResponseWriter, request *http.Request) {
		path := development.RepositoryPath(request.URL.Query().Get("path"))
		document := development.RepositoryDocument{Path: path, Content: content}
		if path != development.ContextPath || document.Validate(path) != nil {
			http.Error(response, "repository artifact is not allowlisted", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(document)
	})
	return mux
}
