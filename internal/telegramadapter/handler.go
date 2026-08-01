package telegramadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type TelegramUserID int64
type Subject string
type Actor string
type Channel string

type TrustedTelegramIdentity struct {
	Subject Subject
	Actor   Actor
	Channel Channel
}

type AvailabilityQuery struct {
	Start time.Time
	End   time.Time
}

type AvailableInterval struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type AvailabilityGateway interface {
	FindAvailability(context.Context, TrustedTelegramIdentity, AvailabilityQuery) ([]AvailableInterval, error)
}

type Config struct {
	WebhookSecret string
	VerifiedUsers map[TelegramUserID]Subject
	ClassifierURL string
	HTTPClient    *http.Client
	Availability  AvailabilityGateway
}

func NewHandler(config Config) http.Handler {
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("POST /telegram/webhook", func(response http.ResponseWriter, request *http.Request) {
		if config.WebhookSecret == "" || request.Header.Get("X-Telegram-Bot-Api-Secret-Token") != config.WebhookSecret {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		var update struct {
			Message struct {
				From struct {
					ID TelegramUserID `json:"id"`
				} `json:"from"`
				Text string `json:"text"`
			} `json:"message"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&update); err != nil || update.Message.Text == "" {
			http.Error(response, "invalid Telegram update", http.StatusBadRequest)
			return
		}
		subject, verified := config.VerifiedUsers[update.Message.From.ID]
		if !verified {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}

		query, err := classify(request.Context(), client, config.ClassifierURL, update.Message.Text)
		if err != nil {
			http.Error(response, "classification failed", http.StatusBadGateway)
			return
		}
		intervals, err := config.Availability.FindAvailability(request.Context(), TrustedTelegramIdentity{
			Subject: subject,
			Actor:   "telegram-agent",
			Channel: "telegram",
		}, query)
		if err != nil {
			http.Error(response, "availability request failed", http.StatusBadGateway)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(struct {
			AvailableIntervals []AvailableInterval `json:"available_intervals"`
		}{AvailableIntervals: intervals})
	})
	return mux
}

func classify(ctx context.Context, client *http.Client, endpoint, text string) (AvailabilityQuery, error) {
	body, err := json.Marshal(map[string]string{"message": text})
	if err != nil {
		return AvailabilityQuery{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return AvailabilityQuery{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return AvailabilityQuery{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return AvailabilityQuery{}, errors.New("classifier returned a non-success response")
	}
	var interpretation struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if err := json.NewDecoder(response.Body).Decode(&interpretation); err != nil {
		return AvailabilityQuery{}, err
	}
	start, err := time.Parse(time.RFC3339, interpretation.Start)
	if err != nil {
		return AvailabilityQuery{}, err
	}
	end, err := time.Parse(time.RFC3339, interpretation.End)
	if err != nil {
		return AvailabilityQuery{}, err
	}
	return AvailabilityQuery{Start: start, End: end}, nil
}
