package testsupport

import (
	"context"

	"github.com/nahtao97/agent-tool-guardrails/internal/approvalauthority"
	"github.com/nahtao97/agent-tool-guardrails/internal/gateway"
)

type HealthyApprovals struct{}

func (HealthyApprovals) ConsumeExact(context.Context, string, approvalauthority.Binding) (approvalauthority.Consumption, error) {
	return approvalauthority.Consumption{}, nil
}

func (HealthyApprovals) Health(context.Context) error { return nil }

type DiscardAudit struct{}

func (DiscardAudit) Record(context.Context, gateway.AuditRecord) error { return nil }
func (DiscardAudit) Health(context.Context) error                      { return nil }
