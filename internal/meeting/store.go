package meeting

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

var ErrProposalNotFound = errors.New("Meeting Proposal not found")
var ErrProposalResolved = errors.New("Meeting Proposal already resolved")

type proposalState string

const (
	pendingState   proposalState = "pending"
	approvingState proposalState = "approving"
	approvedState  proposalState = "approved"
	deniedState    proposalState = "denied"
)

type Store struct {
	mu        sync.RWMutex
	next      uint64
	proposals map[ProposalID]Proposal
	states    map[ProposalID]proposalState
}

func NewStore() *Store {
	return &Store{proposals: make(map[ProposalID]Proposal), states: make(map[ProposalID]proposalState)}
}

func (store *Store) Submit(requester string, input ProposalInput) Proposal {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.next++
	id := ProposalID(fmt.Sprintf("proposal-%d", store.next))
	proposal := Proposal{
		ProposalID:       id,
		TraceID:          TraceID(fmt.Sprintf("meeting-trace-%d", store.next)),
		Start:            input.Start.UTC().Format("2006-01-02T15:04:05Z07:00"),
		End:              input.End.UTC().Format("2006-01-02T15:04:05Z07:00"),
		RequesterSubject: requester,
		Reason:           strings.TrimSpace(input.Reason),
		Contact:          strings.TrimSpace(input.Contact),
	}
	store.proposals[id] = proposal
	store.states[id] = pendingState
	return proposal
}

func (store *Store) Review(id ProposalID) (Operation, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	proposal, ok := store.proposals[id]
	if !ok {
		return Operation{}, ErrProposalNotFound
	}
	if store.states[id] == deniedState {
		return Operation{}, ErrProposalResolved
	}
	return operationFor(proposal), nil
}

func operationFor(proposal Proposal) Operation {
	return Operation{
		Tool:    "calendar.create_event",
		TraceID: proposal.TraceID,
		Arguments: EventArguments{
			ProposalID:       proposal.ProposalID,
			Start:            proposal.Start,
			End:              proposal.End,
			RequesterSubject: proposal.RequesterSubject,
			Reason:           proposal.Reason,
			Contact:          proposal.Contact,
			IdempotencyKey:   "meeting-proposal:" + string(proposal.ProposalID),
		},
	}
}

func (store *Store) Deny(id ProposalID) (Denial, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.proposals[id]; !ok {
		return Denial{}, ErrProposalNotFound
	}
	if store.states[id] != pendingState {
		return Denial{}, ErrProposalResolved
	}
	store.states[id] = deniedState
	return Denial{ProposalID: id, Status: "denied"}, nil
}

func (store *Store) BeginApproval(id ProposalID) (Operation, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	proposal, ok := store.proposals[id]
	if !ok {
		return Operation{}, false, ErrProposalNotFound
	}
	switch store.states[id] {
	case pendingState:
		store.states[id] = approvingState
		return operationFor(proposal), false, nil
	case approvedState:
		return operationFor(proposal), true, nil
	default:
		return Operation{}, false, ErrProposalResolved
	}
}

func (store *Store) CompleteApproval(id ProposalID) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.states[id] == approvingState {
		store.states[id] = approvedState
	}
}

func (store *Store) CancelApproval(id ProposalID) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.states[id] == approvingState {
		store.states[id] = pendingState
	}
}
