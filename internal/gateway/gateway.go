package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const coffeeStationStatusTool = "coffee_station.get_status"

type SecurityContext struct {
	Subject string `json:"subject"`
}

type PolicyInput struct {
	SecurityContext SecurityContext `json:"security_context"`
	Tool            string          `json:"tool"`
	Arguments       any             `json:"arguments"`
}

type PolicyDecision struct {
	Allow      bool   `json:"allow"`
	DecisionID string `json:"decision_id"`
}

type PolicyClient interface {
	Decide(context.Context, PolicyInput) (PolicyDecision, error)
	Health(context.Context) error
}

type CoffeeStation interface {
	Status(context.Context, string) (CoffeeStationStatus, error)
}

type CoffeeStationStatus struct {
	StationID string `json:"station_id"`
	State     string `json:"state"`
}

type Dependencies struct {
	SecurityContext SecurityContext
	Policy          PolicyClient
	CoffeeStation   CoffeeStation
}

type coffeeStationStatusInput struct {
	StationID string `json:"station_id" jsonschema:"the fixed identifier of the coffee station"`
}

func NewHandler(deps Dependencies) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "agent-tool-guardrails",
		Version: "v0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        coffeeStationStatusTool,
		Description: "Read the status of the demo coffee station.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input coffeeStationStatusInput) (*mcp.CallToolResult, CoffeeStationStatus, error) {
		decision, err := deps.Policy.Decide(ctx, PolicyInput{
			SecurityContext: deps.SecurityContext,
			Tool:            coffeeStationStatusTool,
			Arguments:       input,
		})
		if err != nil {
			return nil, CoffeeStationStatus{}, err
		}
		result := &mcp.CallToolResult{Meta: mcp.Meta{"decision_id": decision.DecisionID}}
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

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	))
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if err := deps.Policy.Health(request.Context()); err != nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(response).Encode(map[string]string{
				"status": "unavailable",
				"policy": "unavailable",
			})
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]string{
			"status": "ready",
			"policy": "ready",
		})
	})
	return mux
}
