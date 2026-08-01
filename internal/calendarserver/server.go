package calendarserver

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/nahtao97/agent-tool-guardrails/internal/freebusy"
)

func NewHandler(expectedCredential string) http.Handler {
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
	return mux
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
