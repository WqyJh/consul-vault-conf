package confz

import (
	"context"
)

type ConfigFetcher interface {
	Fetch(ctx context.Context, key string) (string, error)
}
