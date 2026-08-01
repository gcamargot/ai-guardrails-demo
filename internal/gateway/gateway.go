package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

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
	findAvailabilityTool    ToolName        = "calendar.find_availability"
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

type AvailabilityQuery struct {
	Start time.Time
	End   time.Time
}

type AvailableInterval struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type FreeBusyView struct {
	AvailableIntervals []AvailableInterval `json:"available_intervals"`
}

type Calendar interface {
	FindAvailability(context.Context, AvailabilityQuery) (FreeBusyView, error)
	Health(context.Context) error
}

type Dependencies struct {
	Identity      IdentityVerifier
	Channel       Channel
	Policy        PolicyClient
	CoffeeStation CoffeeStation
	Calendar      Calendar
}

type coffeeStationStatusInput struct {
	StationID StationID `json:"station_id" jsonschema:"the fixed identifier of the coffee station"`
}

type findAvailabilityInput struct {
	Start string `json:"start" jsonschema:"RFC3339 start of the requested availability window"`
	End   string `json:"end" jsonschema:"RFC3339 end of the requested availability window"`
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
			result, err := next(ctx, method, request)
			if err != nil {
				return nil, err
			}
			listed, ok := result.(*mcp.ListToolsResult)
			if !ok {
				return &mcp.ListToolsResult{}, nil
			}
			filtered := make([]*mcp.Tool, 0, len(listed.Tools))
			for _, tool := range listed.Tools {
				decision, decisionErr := deps.Policy.Decide(ctx, PolicyInput{
					SecurityContext: securityContext,
					Operation:       discoverOperation,
					Tool:            ToolName(tool.Name),
				})
				if decisionErr == nil && decision.Allow {
					filtered = append(filtered, tool)
				}
			}
			listed.Tools = filtered
			return listed, nil
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

	mcp.AddTool(server, &mcp.Tool{
		Name:        string(findAvailabilityTool),
		Description: "Return only available intervals from the isolated demo calendar.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input findAvailabilityInput) (*mcp.CallToolResult, FreeBusyView, error) {
		start, startErr := time.Parse(time.RFC3339, input.Start)
		end, endErr := time.Parse(time.RFC3339, input.End)
		if startErr != nil || endErr != nil || !end.After(start) {
			result := &mcp.CallToolResult{}
			result.SetError(errors.New("invalid availability window"))
			return result, FreeBusyView{}, nil
		}
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: securityContext,
			Operation:       executeOperation,
			Tool:            findAvailabilityTool,
			Arguments:       input,
		})
		if err != nil {
			return nil, FreeBusyView{}, err
		}
		result := &mcp.CallToolResult{Meta: mcp.Meta{
			"decision_id":     decision.DecisionID,
			"policy_revision": decision.PolicyRevision,
		}}
		if !decision.Allow {
			result.SetError(errors.New("tool call denied by policy"))
			return result, FreeBusyView{}, nil
		}
		if deps.Calendar == nil {
			return nil, FreeBusyView{}, errors.New("calendar is unavailable")
		}
		view, err := deps.Calendar.FindAvailability(ctx, AvailabilityQuery{Start: start, End: end})
		if err != nil {
			return nil, FreeBusyView{}, err
		}
		previousEnd := start
		for _, interval := range view.AvailableIntervals {
			intervalStart, intervalStartErr := time.Parse(time.RFC3339, interval.Start)
			intervalEnd, intervalEndErr := time.Parse(time.RFC3339, interval.End)
			if intervalStartErr != nil || intervalEndErr != nil ||
				intervalStart.Before(start) || intervalEnd.After(end) ||
				!intervalEnd.After(intervalStart) || intervalStart.Before(previousEnd) {
				result.SetError(errors.New("calendar returned an invalid Free/Busy View"))
				return result, FreeBusyView{}, nil
			}
			previousEnd = intervalEnd
		}
		return result, view, nil
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
		if deps.Calendar != nil {
			if err := deps.Calendar.Health(request.Context()); err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(response).Encode(map[string]string{
					"status":   "unavailable",
					"policy":   "ready",
					"resource": "unavailable",
				})
				return
			}
		}
		_ = json.NewEncoder(response).Encode(map[string]string{
			"status":   "ready",
			"policy":   "ready",
			"resource": "ready",
		})
	}
}
