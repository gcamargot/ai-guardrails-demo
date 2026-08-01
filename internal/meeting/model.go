package meeting

import "time"

type ProposalID string
type TraceID string
type ApprovalToken string

type ProposalInput struct {
	Start   time.Time
	End     time.Time
	Reason  string
	Contact string
}

type Proposal struct {
	ProposalID       ProposalID `json:"proposal_id"`
	TraceID          TraceID    `json:"trace_id"`
	Start            string     `json:"start"`
	End              string     `json:"end"`
	RequesterSubject string     `json:"requester_subject"`
	Reason           string     `json:"reason"`
	Contact          string     `json:"contact"`
}

type Operation struct {
	Tool      string         `json:"tool"`
	Arguments EventArguments `json:"arguments"`
	TraceID   TraceID        `json:"trace_id"`
	Approval  ApprovalToken  `json:"approval,omitempty"`
}

type EventArguments struct {
	ProposalID       ProposalID `json:"proposal_id"`
	Start            string     `json:"start"`
	End              string     `json:"end"`
	RequesterSubject string     `json:"requester_subject"`
	Reason           string     `json:"reason"`
	Contact          string     `json:"contact"`
	IdempotencyKey   string     `json:"idempotency_key"`
}

type Event struct {
	EventID    string `json:"event_id"`
	Created    bool   `json:"created"`
	EventCount int    `json:"event_count"`
}

type Denial struct {
	ProposalID ProposalID `json:"proposal_id"`
	Status     string     `json:"status"`
}

func (id ProposalID) String() string { return string(id) }
