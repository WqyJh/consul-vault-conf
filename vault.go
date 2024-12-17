package confz

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

const (
	EnvVaultAddr     = "VAULT_ADDR"
	EnvVaultRoleId   = "VAULT_ROLE_ID"
	EnvVaultSecretId = "VAULT_SECRET_ID"
	EnvVaultTmpDir   = "VAULT_TMP_DIR"
)

func NewEnvAppRoleVaultClient() (*vault.Client, error) {
	addr := os.Getenv(EnvVaultAddr)
	roleId := os.Getenv(EnvVaultRoleId)
	secretId := os.Getenv(EnvVaultSecretId)
	return NewAppRoleVaultClient(addr, roleId, secretId)
}

func NewAppRoleVaultClient(
	addr string,
	roleId string,
	secretId string,
) (*vault.Client, error) {
	ctx := context.Background()
	client, err := vault.New(
		vault.WithAddress(addr),
	)
	if err != nil {
		return nil, err
	}

	response, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   roleId,
		SecretId: secretId,
	})
	if err != nil {
		return nil, err
	}

	err = client.SetToken(response.Auth.ClientToken)
	if err != nil {
		return nil, err
	}

	return client, nil
}

type VaultSecretFetcher struct {
	client *vault.Client
	cache  *cache.Cache
}

func NewVaultSecretFetcher(client *vault.Client) *VaultSecretFetcher {
	cache := cache.New(cache.NoExpiration, cache.NoExpiration)

	return &VaultSecretFetcher{
		client: client,
		cache:  cache,
	}
}

func (f *VaultSecretFetcher) Close() error {
	f.cache.Flush()
	return nil
}

// Fetch returns the value of the key in the given path.
// path format: {mount}/{path}/{key}
// cache key: {mount}/{path}
func (f *VaultSecretFetcher) Fetch(ctx context.Context, secretKey string) (string, error) {
	splited := strings.Split(secretKey, "/")
	if len(splited) < 3 {
		return "", errors.Errorf("invalid secret key: %s", secretKey)
	}
	// first part is mount
	mount := splited[0]
	// last part is key
	key := splited[len(splited)-1]
	// the rest is path
	path := strings.Join(splited[1:len(splited)-1], "/")

	cacheKey := mount + "/" + path

	if value, ok := f.cache.Get(cacheKey); ok {
		if valueMap, ok := value.(schema.KvV2ReadResponse); ok {
			if value, ok := valueMap.Data[key].(string); ok {
				return f.decode(valueMap, key, value)
			}
		}
	}

	response, err := f.client.Secrets.KvV2Read(ctx, path, vault.WithMountPath(mount))
	if err != nil {
		return "", errors.Wrapf(err, "KvV2Read %s", path)
	}

	// logx.Debugw("vault response", logx.Field("response", response), logx.Field("key", secretKey))

	f.cache.Set(cacheKey, response.Data, cache.DefaultExpiration)

	value := response.Data.Data[key]
	if value == nil {
		return "", errors.Errorf("secret value is nil: %s", secretKey)
	}

	if val, ok := value.(string); ok {
		return f.decode(response.Data, key, val)
	}

	return "", errors.Errorf("invalid secret value type: %T", value)
}

func (f *VaultSecretFetcher) decode(response schema.KvV2ReadResponse, key string, value string) (string, error) {
	var isFile bool
	if meta, ok := response.Metadata["custom_metadata"].(map[string]interface{}); ok {
		if metaValue, ok := meta[key].(string); ok {
			if metaValue == "is-file" {
				isFile = true
			}
		}
	}
	if isFile {
		filename := Md5Hex([]byte(value))
		dir := getTmpDir()
		filename = filepath.Join(dir, filename)
		err := os.WriteFile(filename, []byte(value), 0600)
		if err != nil {
			return "", errors.Wrapf(err, "WriteFile %s to %s", key, filename)
		}
		return filename, nil
	}
	return value, nil
}

func getTmpDir() string {
	dir := os.Getenv(EnvVaultTmpDir)
	if dir == "" {
		dir = "/tmp/vault"
	}
	_ = os.MkdirAll(dir, 0700)
	return dir
}

type LazyVaultSecretFetcher struct {
	fetcher *VaultSecretFetcher
}

func NewLazyVaultSecretFetcher() *LazyVaultSecretFetcher {
	return &LazyVaultSecretFetcher{}
}

func (f *LazyVaultSecretFetcher) Fetch(ctx context.Context, secretKey string) (string, error) {
	if f.fetcher == nil {
		client, err := NewEnvAppRoleVaultClient()
		if err != nil {
			return "", err
		}
		f.fetcher = NewVaultSecretFetcher(client)
	}
	return f.fetcher.Fetch(ctx, secretKey)
}
