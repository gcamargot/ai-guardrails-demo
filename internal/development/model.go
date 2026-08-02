package development

import (
	"errors"
	"strings"
)

type RepositoryPath string

const ContextPath RepositoryPath = "CONTEXT.md"

type RepositoryDocument struct {
	Path    RepositoryPath `json:"path"`
	Content string         `json:"content"`
}

func (document RepositoryDocument) Validate(requested RepositoryPath) error {
	if requested != ContextPath || document.Path != requested || strings.TrimSpace(document.Content) == "" || len(document.Content) > 64*1024 {
		return errors.New("invalid repository document")
	}
	return nil
}
