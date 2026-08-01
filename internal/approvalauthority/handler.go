package approvalauthority

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Binding struct {
	Subject   string `json:"subject"`
	Actor     string `json:"actor"`
	Tool      string `json:"tool"`
	Arguments any    `json:"arguments"`
	TraceID   string `json:"trace_id"`
}

type Config struct {
	SigningKey         []byte
	IssuerCredential   string
	ConsumerCredential string
	OwnerSubject       string
	TTL                time.Duration
	Now                func() time.Time
}

type authority struct {
	config Config
	mu     sync.Mutex
	used   map[string]struct{}
}

type claims struct {
	Subject       string `json:"subject"`
	Actor         string `json:"actor"`
	Tool          string `json:"tool"`
	ArgumentsHash string `json:"arguments_hash"`
	TraceID       string `json:"trace_id"`
	ExpiresAt     int64  `json:"expires_at"`
	Nonce         string `json:"nonce"`
}

func NewHandler(config Config) http.Handler {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.TTL <= 0 {
		config.TTL = 2 * time.Minute
	}
	service := &authority{config: config, used: make(map[string]struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("POST /approvals/issue", service.authenticate(config.IssuerCredential, service.issue))
	mux.HandleFunc("POST /approvals/consume", service.authenticate(config.ConsumerCredential, service.consume))
	return mux
}

func (service *authority) authenticate(credential string, next http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		want := "Bearer " + credential
		if credential == "" || !hmac.Equal([]byte(request.Header.Get("Authorization")), []byte(want)) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(response, request)
	}
}

func (service *authority) issue(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Binding Binding `json:"binding"`
	}
	if decodeStrict(request.Body, &input) != nil || !service.validBinding(input.Binding) {
		http.Error(response, "invalid exact approval", http.StatusBadRequest)
		return
	}
	argumentHash, err := hashArguments(input.Binding.Arguments)
	if err != nil {
		http.Error(response, "invalid exact approval", http.StatusBadRequest)
		return
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(response, "approval unavailable", http.StatusServiceUnavailable)
		return
	}
	payload, err := json.Marshal(claims{
		Subject:       input.Binding.Subject,
		Actor:         input.Binding.Actor,
		Tool:          input.Binding.Tool,
		ArgumentsHash: argumentHash,
		TraceID:       input.Binding.TraceID,
		ExpiresAt:     service.config.Now().Add(service.config.TTL).Unix(),
		Nonce:         hex.EncodeToString(nonceBytes),
	})
	if err != nil {
		http.Error(response, "approval unavailable", http.StatusServiceUnavailable)
		return
	}
	token := service.sign(payload)
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(map[string]string{"approval": token})
}

func (service *authority) consume(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Approval string  `json:"approval"`
		Binding  Binding `json:"binding"`
	}
	if decodeStrict(request.Body, &input) != nil || input.Approval == "" {
		http.Error(response, "invalid Approval", http.StatusBadRequest)
		return
	}
	payload, verified := service.verify(input.Approval)
	if !verified {
		http.Error(response, "Approval denied", http.StatusForbidden)
		return
	}
	var approved claims
	if json.Unmarshal(payload, &approved) != nil {
		http.Error(response, "Approval denied", http.StatusForbidden)
		return
	}
	argumentHash, err := hashArguments(input.Binding.Arguments)
	if err != nil || approved.Subject != input.Binding.Subject || approved.Actor != input.Binding.Actor ||
		approved.Tool != input.Binding.Tool || approved.TraceID != input.Binding.TraceID ||
		approved.ArgumentsHash != argumentHash || !service.config.Now().Before(time.Unix(approved.ExpiresAt, 0)) {
		http.Error(response, "Approval denied", http.StatusForbidden)
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if _, replayed := service.used[approved.Nonce]; replayed {
		http.Error(response, "Approval already consumed", http.StatusConflict)
		return
	}
	service.used[approved.Nonce] = struct{}{}
	response.WriteHeader(http.StatusNoContent)
}

func (service *authority) validBinding(binding Binding) bool {
	return len(service.config.SigningKey) >= 32 && binding.Subject == service.config.OwnerSubject &&
		binding.Actor == "telegram-agent" && binding.Tool == "calendar.create_event" && binding.TraceID != "" && binding.Arguments != nil
}

func (service *authority) sign(payload []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, service.config.SigningKey)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (service *authority) verify(token string) ([]byte, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, false
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, service.config.SigningKey)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	return payload, err == nil
}

func hashArguments(arguments any) (string, error) {
	canonical, err := json.Marshal(arguments)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func decodeStrict(body io.Reader, value any) error {
	decoder := json.NewDecoder(io.LimitReader(body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}
