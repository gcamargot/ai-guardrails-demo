package meeting

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

var ErrProposalNotFound = errors.New("Meeting Proposal not found")

type Store struct {
	mu        sync.RWMutex
	next      uint64
	proposals map[ProposalID]Proposal
	denied    map[ProposalID]struct{}
}

func NewStore() *Store {
	return &Store{proposals: make(map[ProposalID]Proposal), denied: make(map[ProposalID]struct{})}
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
	return proposal
}

func (store *Store) Review(id ProposalID) (Operation, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	proposal, ok := store.proposals[id]
	_, denied := store.denied[id]
	if !ok || denied {
		return Operation{}, ErrProposalNotFound
	}
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
	}, nil
}

func (store *Store) Deny(id ProposalID) (Denial, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.proposals[id]; !ok {
		return Denial{}, ErrProposalNotFound
	}
	store.denied[id] = struct{}{}
	return Denial{ProposalID: id, Status: "denied"}, nil
}
