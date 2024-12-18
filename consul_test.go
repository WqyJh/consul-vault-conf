package confz_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	confz "github.com/WqyJh/consul-vault-conf"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	capi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/consul"
)

type ConsulConfig struct {
	ConsulAddr    string
	ConsulToken   string
	ReadonlyToken string
}

func TestConsul(t *testing.T) {
	ctx := context.Background()
	consulContainer, consulToken, err := setupConsulContainer(ctx)
	require.NoError(t, err)
	defer testcontainers.TerminateContainer(consulContainer)

	expected := `Test:
  Hello: World
  Encrypted: ENC~b2/w1Q5OzFI3RdVK28dntMc5gUoIJ2TKZMLf0GfrIOBYjFcPTWh7EAukti0bUQ==
  Encrypted2: SEC~kv/unittest/encrypted/key1
  Encrypted3: SEC~kv/unittest/encrypted/key2
  Encrypted4: SEC~kv/unittest/encrypted2/key1`

	consulConfig := bootstrapConsul(t, consulContainer, consulToken, &capi.KVPair{
		Key:   "unittest/config.yaml",
		Value: []byte(expected),
	})

	t.Logf("consulConfig: %+v", consulConfig)

	vaultContainer, vaultToken, err := setupVaultContainer(ctx)
	require.NoError(t, err)
	defer testcontainers.TerminateContainer(vaultContainer)

	vaultConfig := bootstrapVault(t, vaultContainer, vaultToken, VaultPair{
		Key: "unittest/encrypted",
		Value: schema.KvV2WriteRequest{
			Data: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}, VaultPair{
		Key: "unittest/encrypted2",
		Value: schema.KvV2WriteRequest{
			Data: map[string]interface{}{
				"key1": "value3",
			},
		},
		Meta: &schema.KvV2WriteMetadataRequest{
			CustomMetadata: map[string]interface{}{
				"key1": "is-file",
			},
		},
	})

	t.Logf("vaultConfig: %+v", vaultConfig)

	os.Setenv("CONSUL_ADDR", consulConfig.ConsulAddr)
	os.Setenv("CONSUL_TOKEN", consulConfig.ConsulToken)
	os.Setenv("VAULT_ADDR", vaultConfig.VaultAddr)
	os.Setenv("VAULT_ROLE_ID", vaultConfig.VaultRoleId)
	os.Setenv("VAULT_SECRET_ID", vaultConfig.VaultSecretId)

	content, err := confz.ConsulGet("unittest/config.yaml")
	require.NoError(t, err)
	require.Equal(t, expected, string(content))

	type Test struct {
		Test Conf
	}

	c := Test{
		Test: Conf{
			Hello:      "World",
			Encrypted:  "ENC~b2/w1Q5OzFI3RdVK28dntMc5gUoIJ2TKZMLf0GfrIOBYjFcPTWh7EAukti0bUQ==",
			Encrypted2: "SEC~kv/unittest/encrypted/key1",
			Encrypted3: "SEC~kv/unittest/encrypted/key2",
			Encrypted4: "SEC~kv/unittest/encrypted2/key1",
		},
	}

	result, err := confz.Decrypt(c)
	require.NoError(t, err)
	decrypted := result.(Test)

	// check decrypted
	require.Equal(t, "World", decrypted.Test.Hello)
	require.Equal(t, "value1", decrypted.Test.Encrypted2)
	require.Equal(t, "value2", decrypted.Test.Encrypted3)
	exists, err := confz.FileExists(decrypted.Test.Encrypted4)
	require.NoError(t, err)
	require.True(t, exists)
	fileContent, err := os.ReadFile(decrypted.Test.Encrypted4)
	require.NoError(t, err)
	require.Equal(t, `value3`, string(fileContent))
	// check original
	require.Equal(t, "World", c.Test.Hello)
	require.Equal(t, "ENC~b2/w1Q5OzFI3RdVK28dntMc5gUoIJ2TKZMLf0GfrIOBYjFcPTWh7EAukti0bUQ==", c.Test.Encrypted)
	require.Equal(t, "SEC~kv/unittest/encrypted/key1", c.Test.Encrypted2)
	require.Equal(t, "SEC~kv/unittest/encrypted/key2", c.Test.Encrypted3)
	require.Equal(t, "SEC~kv/unittest/encrypted2/key1", c.Test.Encrypted4)

	err = confz.DecryptInplace(&c)
	require.NoError(t, err)

	// check inplace
	require.Equal(t, "World", c.Test.Hello)
	require.Equal(t, "value1", c.Test.Encrypted2)
	require.Equal(t, "value2", c.Test.Encrypted3)
	exists, err = confz.FileExists(c.Test.Encrypted4)
	require.NoError(t, err)
	require.True(t, exists)
	content, err = os.ReadFile(c.Test.Encrypted4)
	require.NoError(t, err)
	require.Equal(t, `value3`, string(content))
}

func setupConsulContainer(ctx context.Context) (testcontainers.Container, string, error) {
	rootToken := uuid.New().String()
	config := fmt.Sprintf(`{
  "server": true,
  "acl": {
    "enabled": true,
    "default_policy": "deny",
    "down_policy": "extend-cache",
    "tokens": {
      "master": "%s"
    }
  }
}`, rootToken)
	consulContainer, err := consul.Run(ctx, "hashicorp/consul:1.20.1", consul.WithConfigString(config))
	if err != nil {
		return nil, "", fmt.Errorf("failed to start container: %s", err)
	}
	return consulContainer, rootToken, nil
}

func bootstrapConsul(t *testing.T, container testcontainers.Container, rootToken string, pairs ...*capi.KVPair) ConsulConfig {
	ctx := context.Background()
	consulAddr, err := container.PortEndpoint(ctx, nat.Port("8500"), "http")
	require.NoError(t, err)

	client, err := capi.NewClient(&capi.Config{
		Address: consulAddr,
		Token:   rootToken,
	})
	require.NoError(t, err)

	acl := client.ACL()

	_, _, err = acl.PolicyCreate(&capi.ACLPolicy{
		Name: "unittest-read",
		Rules: `key_prefix "unittest/" {
	policy = "read"
}`,
	}, nil)
	require.NoError(t, err)

	token, _, err := acl.TokenCreate(&capi.ACLToken{
		Description: "unittest-token",
		Policies: []*capi.ACLTokenPolicyLink{
			{
				Name: "unittest-read",
			},
		},
	}, nil)
	require.NoError(t, err)

	kv := client.KV()
	for _, pair := range pairs {
		_, err = kv.Put(pair, nil)
		require.NoError(t, err)
	}

	return ConsulConfig{
		ConsulAddr:    consulAddr,
		ConsulToken:   rootToken,
		ReadonlyToken: token.SecretID,
	}
}
