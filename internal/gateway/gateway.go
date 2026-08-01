package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Subject string
type Actor string
type Channel string
type Capability string
type ToolName string
type PolicyOperation string
type StationID string

const (
	coffeeStationStatusTool ToolName        = "coffee_station.get_status"
	discoverOperation       PolicyOperation = "discover"
	executeOperation        PolicyOperation = "execute"
)

type SecurityContext struct {
	Subject          Subject      `json:"subject"`
	Actor            Actor        `json:"actor"`
	Channel          Channel      `json:"channel"`
	TurnCapabilities []Capability `json:"turn_capabilities"`
}

type TrustedIdentity struct {
	Subject          Subject
	Actor            Actor
	TurnCapabilities []Capability
}

type IdentityVerifier interface {
	Verify(context.Context, string) (TrustedIdentity, error)
}

type IdentityVerifierFunc func(context.Context, string) (TrustedIdentity, error)

func (verify IdentityVerifierFunc) Verify(ctx context.Context, token string) (TrustedIdentity, error) {
	return verify(ctx, token)
}

type PolicyInput struct {
	SecurityContext SecurityContext `json:"security_context"`
	Operation       PolicyOperation `json:"operation"`
	Tool            ToolName        `json:"tool"`
	Arguments       any             `json:"arguments"`
}

type PolicyDecision struct {
	Allow          bool   `json:"allow"`
	DecisionID     string `json:"decision_id"`
	PolicyRevision string `json:"policy_revision"`
}

type PolicyClient interface {
	Decide(context.Context, PolicyInput) (PolicyDecision, error)
	Health(context.Context) error
}

type CoffeeStation interface {
	Status(context.Context, StationID) (CoffeeStationStatus, error)
	Health(context.Context) error
}

type CoffeeStationStatus struct {
	StationID StationID `json:"station_id"`
	State     string    `json:"state"`
}

type Dependencies struct {
	Identity      IdentityVerifier
	Channel       Channel
	Policy        PolicyClient
	CoffeeStation CoffeeStation
}

type coffeeStationStatusInput struct {
	StationID StationID `json:"station_id" jsonschema:"the fixed identifier of the coffee station"`
}

func NewHandler(deps Dependencies) http.Handler {
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(request *http.Request) *mcp.Server {
			identity, ok := request.Context().Value(identityContextKey{}).(TrustedIdentity)
			if !ok {
				return newMCPServer(deps, SecurityContext{})
			}
			return newMCPServer(deps, SecurityContext{
				Subject:          identity.Subject,
				Actor:            identity.Actor,
				Channel:          deps.Channel,
				TurnCapabilities: identity.TurnCapabilities,
			})
		},
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", authenticate(deps.Identity, mcpHandler))
	mux.HandleFunc("GET /healthz", healthHandler(deps))
	return mux
}

type identityContextKey struct{}

func authenticate(identity IdentityVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		const prefix = "Bearer "
		authorization := request.Header.Get("Authorization")
		if identity == nil || !strings.HasPrefix(authorization, prefix) || len(authorization) == len(prefix) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		trusted, err := identity.Verify(request.Context(), strings.TrimPrefix(authorization, prefix))
		if err != nil {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), identityContextKey{}, trusted)))
	})
}

func newMCPServer(deps Dependencies, securityContext SecurityContext) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "agent-tool-guardrails",
		Version: "v0.1.0",
	}, nil)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			if method != "tools/list" {
				return next(ctx, method, request)
			}
			decision, err := deps.Policy.Decide(ctx, PolicyInput{
				SecurityContext: securityContext,
				Operation:       discoverOperation,
				Tool:            coffeeStationStatusTool,
			})
			if err != nil || !decision.Allow {
				return &mcp.ListToolsResult{}, nil
			}
			return next(ctx, method, request)
		}
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(coffeeStationStatusTool),
		Description: "Read the status of the demo coffee station.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input coffeeStationStatusInput) (*mcp.CallToolResult, CoffeeStationStatus, error) {
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext,
			Operation:       executeOperation,
			Tool:            coffeeStationStatusTool,
			Arguments:       input,
		})
		if err != nil {
			return nil, CoffeeStationStatus{}, err
		}
		result := &mcp.CallToolResult{Meta: mcp.Meta{
			"decision_id":     decision.DecisionID,
			"policy_revision": decision.PolicyRevision,
		}}
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, CoffeeStationStatus{}, nil
		}

		status, err := deps.CoffeeStation.Status(ctx, input.StationID)
		if err != nil {
			return nil, CoffeeStationStatus{}, err
		}
		if status.StationID != input.StationID || (status.State != "ready" && status.State != "offline") {
			result.SetError(errors.New("adapter returned invalid coffee station status"))
			return result, CoffeeStationStatus{}, nil
		}
		return result, status, nil
	})

	return server
}

func healthHandler(deps Dependencies) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if err := deps.Policy.Health(request.Context()); err != nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(map[string]string{
				"status": "unavailable",
				"policy": "unavailable",
			})
			return
		}
		if err := deps.CoffeeStation.Health(request.Context()); err != nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(map[string]string{
				"status":   "unavailable",
				"policy":   "ready",
				"resource": "unavailable",
			})
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]string{
			"status":   "ready",
			"policy":   "ready",
			"resource": "ready",
		})
	}
}
