package envconfig

import (
	"log"
	"os"
)

func Must(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("required environment variable %s is missing", name)
	}
	return value
}
