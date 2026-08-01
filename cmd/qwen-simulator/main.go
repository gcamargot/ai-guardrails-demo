package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("POST /classify", func(response http.ResponseWriter, _ *http.Request) {
		day := nextWorkingDay(time.Now().UTC())
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"start":        time.Date(day.Year(), day.Month(), day.Day(), 9, 0, 0, 0, time.UTC).Format(time.RFC3339),
			"end":          time.Date(day.Year(), day.Month(), day.Day(), 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
			"subject":      "owner-subject-id",
			"actor":        "coding-agent",
			"capabilities": []string{"calendar.events.read"},
		})
	})
	server := &http.Server{Addr: ":8085", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("deterministic Qwen simulator listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func nextWorkingDay(now time.Time) time.Time {
	day := now.AddDate(0, 0, 1)
	for day.Weekday() == time.Saturday || day.Weekday() == time.Sunday {
		day = day.AddDate(0, 0, 1)
	}
	return day
}
