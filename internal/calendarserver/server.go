package calendarserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/freebusy"
	"github.com/nahtao97/agent-tool-guardrails/internal/meeting"
)

func NewHandler(expectedCredential string) http.Handler {
	type storedEvent struct {
		arguments meeting.EventArguments
		eventID   string
	}
	var state struct {
		sync.Mutex
		events map[string]storedEvent
	}
	state.events = make(map[string]storedEvent)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("GET /free-busy", func(response http.ResponseWriter, request *http.Request) {
		if expectedCredential == "" || request.Header.Get("Authorization") != "Bearer "+expectedCredential {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		start, startErr := time.Parse(time.RFC3339, request.URL.Query().Get("start"))
		end, endErr := time.Parse(time.RFC3339, request.URL.Query().Get("end"))
		if startErr != nil || endErr != nil || !end.After(start) {
			http.Error(response, "invalid availability window", http.StatusBadRequest)
			return
		}

		occupiedStart := time.Date(start.Year(), start.Month(), start.Day(), 10, 30, 0, 0, time.UTC)
		occupiedEnd := occupiedStart.Add(30 * time.Minute)
		intervals := make([]freebusy.AvailableInterval, 0, 2)
		if start.Before(occupiedStart) {
			freeEnd := minTime(end, occupiedStart)
			if freeEnd.After(start) {
				intervals = append(intervals, interval(start, freeEnd))
			}
		}
		if end.After(occupiedEnd) {
			freeStart := maxTime(start, occupiedEnd)
			if end.After(freeStart) {
				intervals = append(intervals, interval(freeStart, end))
			}
		}
		if !start.Before(occupiedEnd) || !end.After(occupiedStart) {
			intervals = []freebusy.AvailableInterval{interval(start, end)}
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(freebusy.View{AvailableIntervals: intervals})
	})
	mux.HandleFunc("GET /metrics", func(response http.ResponseWriter, _ *http.Request) {
		state.Lock()
		defer state.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(struct {
			EventCount int `json:"event_count"`
		}{EventCount: len(state.events)})
	})
	mux.HandleFunc("POST /events", func(response http.ResponseWriter, request *http.Request) {
		if expectedCredential == "" || request.Header.Get("Authorization") != "Bearer "+expectedCredential {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		var arguments meeting.EventArguments
		decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&arguments) != nil || !validEventArguments(arguments) {
			http.Error(response, "invalid event", http.StatusBadRequest)
			return
		}
		state.Lock()
		defer state.Unlock()
		if existing, ok := state.events[arguments.IdempotencyKey]; ok {
			if existing.arguments != arguments {
				http.Error(response, "idempotency conflict", http.StatusConflict)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(meeting.Event{EventID: existing.eventID, Created: false})
			return
		}
		eventID := "demo-event-" + strings.TrimPrefix(arguments.ProposalID.String(), "proposal-")
		state.events[arguments.IdempotencyKey] = storedEvent{arguments: arguments, eventID: eventID}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(meeting.Event{EventID: eventID, Created: true})
	})
	return mux
}

func validEventArguments(arguments meeting.EventArguments) bool {
	start, startErr := time.Parse(time.RFC3339, arguments.Start)
	end, endErr := time.Parse(time.RFC3339, arguments.End)
	return startErr == nil && endErr == nil && end.After(start) && end.Sub(start) <= 2*time.Hour &&
		arguments.ProposalID != "" && arguments.RequesterSubject != "" && strings.TrimSpace(arguments.Reason) != "" &&
		strings.TrimSpace(arguments.Contact) != "" && arguments.IdempotencyKey == "meeting-proposal:"+arguments.ProposalID.String()
}

func interval(start, end time.Time) freebusy.AvailableInterval {
	return freebusy.AvailableInterval{Start: freebusy.NewRFC3339(start), End: freebusy.NewRFC3339(end)}
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func maxTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}
