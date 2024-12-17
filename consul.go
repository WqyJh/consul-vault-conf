package confz

import (
	"fmt"
	"log"
	"os"

	"github.com/asim/go-micro/v3/util/file"
	capi "github.com/hashicorp/consul/api"
	"github.com/zeromicro/go-zero/core/conf"
)

const (
	EnvConsulAddr  = "CONSUL_ADDR"
	EnvConsulToken = "CONSUL_TOKEN"
)

func LoadByConsul(key string, v interface{}) error {
	addr := os.Getenv(EnvConsulAddr)
	token := os.Getenv(EnvConsulToken)
	if addr == "" || token == "" {
		return fmt.Errorf("consul addr or token is not set")
	}
	client, err := capi.NewClient(&capi.Config{
		Address: addr,
		Token:   token,
	})
	if err != nil {
		return err
	}
	kv := client.KV()
	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return err
	}
	if pair == nil {
		return fmt.Errorf("consul key %s not found", key)
	}
	return conf.LoadConfigFromYamlBytes(pair.Value, v)
}

func Load[T any](path string, opts ...conf.Option) (T, error) {
	var v T
	exists, err := file.Exists(path)
	if err != nil {
		return v, err
	}
	if exists {
		err := conf.Load(path, &v, opts...)
		if err == nil {
			return v, nil
		}
	}
	err = LoadByConsul(path, &v)
	if err != nil {
		return v, err
	}
	return v, nil
}

func SecurityLoad[T any](path string, opts ...conf.Option) (T, error) {
	v, err := Load[T](path, opts...)
	if err != nil {
		return v, err
	}

	secretFetcher := NewLazyVaultSecretFetcher()
	encDecoder := NewDefaultEncDecoder()
	decoded, err := Decode(v, secretFetcher, encDecoder)
	if err != nil {
		return v, err
	}

	return decoded.(T), nil
}

func SecurityMustLoad[T any](path string, opts ...conf.Option) T {
	v, err := SecurityLoad[T](path, opts...)
	if err != nil {
		log.Fatalf("failed to load config from consul: %v", err)
	}
	return v
}