package confz

import (
	"fmt"
	"os"
	"reflect"

	capi "github.com/hashicorp/consul/api"
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
	secretFetcher := NewLazyVaultSecretFetcher()
	encDecoder := NewDefaultEncDecoder()
	decoded, err := Decode(v, secretFetcher, encDecoder)
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
