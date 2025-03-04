package confz

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	capi "github.com/hashicorp/consul/api"
	"github.com/patrickmn/go-cache"
)

const (
	EnvConsulAddr  = "CONSUL_ADDR"
	EnvConsulToken = "CONSUL_TOKEN"
)

func ConsulGet(key string) ([]byte, error) {
	addr := os.Getenv(EnvConsulAddr)
	token := os.Getenv(EnvConsulToken)
	if addr == "" || token == "" {
		return nil, fmt.Errorf("consul addr or token is not set")
	}
	client, err := capi.NewClient(&capi.Config{
		Address: addr,
		Token:   token,
	})
	if err != nil {
		return nil, err
	}
	kv := client.KV()
	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, fmt.Errorf("consul key %s not found", key)
	}
	return pair.Value, nil
}

func Decrypt(v any) (any, error) {
	configFetcher := NewLazyConsulConfigFetcher()
	secretFetcher := NewLazyVaultSecretFetcher()
	encDecoder := NewDefaultEncDecoder()
	decoded, err := Decode(v, configFetcher, secretFetcher, encDecoder)
	if err != nil {
		return v, err
	}
	return decoded, nil
}

func DecryptInplace(v any) error {
	decoded, err := Decrypt(v)
	if err != nil {
		return err
	}
	if reflect.TypeOf(v).Kind() == reflect.Ptr {
		reflect.ValueOf(v).Elem().Set(reflect.ValueOf(decoded).Elem())
		return nil
	}
	reflect.ValueOf(v).Set(reflect.ValueOf(decoded))
	return nil
}

type ConsulConfigFetcher struct {
	client *capi.Client
	cache  *cache.Cache
}

func NewConsulConfigFetcher(client *capi.Client) *ConsulConfigFetcher {
	cache := cache.New(cache.NoExpiration, cache.NoExpiration)

	return &ConsulConfigFetcher{
		client: client,
		cache:  cache,
	}
}

func (f *ConsulConfigFetcher) Close() error {
	f.cache.Flush()
	return nil
}

func (f *ConsulConfigFetcher) Fetch(ctx context.Context, key string) (string, error) {
	key = strings.TrimPrefix(key, "kv/")
	kv := f.client.KV()
	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return "", err
	}
	if pair == nil {
		return "", fmt.Errorf("consul key %s not found", key)
	}
	return string(pair.Value), nil
}

type LazyConsulConfigFetcher struct {
	fetcher *ConsulConfigFetcher
}

func NewLazyConsulConfigFetcher() *LazyConsulConfigFetcher {
	return &LazyConsulConfigFetcher{}
}

func (f *LazyConsulConfigFetcher) Fetch(ctx context.Context, key string) (string, error) {
	if f.fetcher == nil {
		client, err := capi.NewClient(&capi.Config{
			Address: os.Getenv(EnvConsulAddr),
			Token:   os.Getenv(EnvConsulToken),
		})
		if err != nil {
			return "", err
		}
		f.fetcher = NewConsulConfigFetcher(client)
	}
	return f.fetcher.Fetch(ctx, key)
}
