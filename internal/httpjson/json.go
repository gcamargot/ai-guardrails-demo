package httpjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const maxDocumentBytes = 1 << 20

func DecodeStrict(reader io.Reader, value any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxDocumentBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func GetStrict[T any](ctx context.Context, client *http.Client, endpoint string) (T, error) {
	var value T
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return value, err
	}
	response, err := client.Do(request)
	if err != nil {
		return value, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return value, fmt.Errorf("HTTP GET returned status %d", response.StatusCode)
	}
	if err := DecodeStrict(response.Body, &value); err != nil {
		return value, err
	}
	return value, nil
}
