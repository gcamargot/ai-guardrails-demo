package outlook

type MessageID string

type SearchQuery struct {
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

type SearchResult struct {
	MessageID  MessageID `json:"message_id"`
	Sender     string    `json:"sender"`
	Subject    string    `json:"subject"`
	ReceivedAt string    `json:"received_at"`
}

type MessageView struct {
	MessageID        MessageID `json:"message_id"`
	Sender           string    `json:"sender"`
	Subject          string    `json:"subject"`
	ReceivedAt       string    `json:"received_at"`
	UntrustedContent string    `json:"untrusted_content"`
}
