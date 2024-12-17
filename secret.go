package confz

import (
	"context"
)

type SecretFetcher interface {
	Fetch(ctx context.Context, key string) (string, error)
}
