package confz

import (
	"context"
	"os"

	"github.com/WqyJh/confcrypt"
)

const (
	EnvConfigKey = "CONFIG_KEY"
)

type EncDecoder struct {
	key string
}

func NewEncDecoder(key string) *EncDecoder {
	return &EncDecoder{key: key}
}

func (d *EncDecoder) Fetch(ctx context.Context, key string) (string, error) {
	decrypted, err := confcrypt.Decrypt(key, d.key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func NewDefaultEncDecoder() *EncDecoder {
	return NewEncDecoder(os.Getenv(EnvConfigKey))
}
