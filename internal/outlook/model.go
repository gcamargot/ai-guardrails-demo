package outlook

import (
	"errors"
	"strings"
	"time"
)

type MessageID string
type Query string
type Sender string
type Subject string
type ReceivedAt string
type UntrustedContent string

type SearchQuery struct {
	Query Query `json:"query"`
	Limit int   `json:"limit"`
}

type SearchResult struct {
	MessageID  MessageID  `json:"message_id"`
	Sender     Sender     `json:"sender"`
	Subject    Subject    `json:"subject"`
	ReceivedAt ReceivedAt `json:"received_at"`
}

type MessageView struct {
	MessageID        MessageID        `json:"message_id"`
	Sender           Sender           `json:"sender"`
	Subject          Subject          `json:"subject"`
	ReceivedAt       ReceivedAt       `json:"received_at"`
	UntrustedContent UntrustedContent `json:"untrusted_content"`
}

func (query SearchQuery) Validate() error {
	text := string(query.Query)
	if text == "" || text != strings.TrimSpace(text) || len(text) > 100 || query.Limit < 1 || query.Limit > 5 {
		return errors.New("invalid Outlook search query")
	}
	return nil
}

func (messageID MessageID) Validate() error {
	if len(messageID) == 0 || len(messageID) > 80 {
		return errors.New("invalid Outlook message identifier")
	}
	for _, character := range messageID {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return errors.New("invalid Outlook message identifier")
		}
	}
	return nil
}

func (result SearchResult) Validate() error {
	if result.MessageID.Validate() != nil || strings.TrimSpace(string(result.Sender)) == "" || strings.TrimSpace(string(result.Subject)) == "" {
		return errors.New("invalid minimized Outlook search result")
	}
	if _, err := time.Parse(time.RFC3339, string(result.ReceivedAt)); err != nil {
		return errors.New("invalid minimized Outlook search result")
	}
	return nil
}

func ValidateSearchResults(messages []SearchResult, limit int) error {
	if len(messages) > limit {
		return errors.New("too many minimized Outlook search results")
	}
	seen := make(map[MessageID]struct{}, len(messages))
	for _, message := range messages {
		if err := message.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[message.MessageID]; duplicate {
			return errors.New("duplicate minimized Outlook search result")
		}
		seen[message.MessageID] = struct{}{}
	}
	return nil
}

func (view MessageView) Validate(expected MessageID) error {
	if view.MessageID != expected || strings.TrimSpace(string(view.Sender)) == "" || strings.TrimSpace(string(view.Subject)) == "" ||
		strings.TrimSpace(string(view.UntrustedContent)) == "" || len(view.UntrustedContent) > 500 {
		return errors.New("invalid minimized Outlook Message View")
	}
	if _, err := time.Parse(time.RFC3339, string(view.ReceivedAt)); err != nil {
		return errors.New("invalid minimized Outlook Message View")
	}
	return nil
}
