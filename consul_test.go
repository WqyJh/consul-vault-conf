package confz_test

import (
	"context"
	"os"
	"testing"

	confz "github.com/WqyJh/consul-vault-conf"
	"github.com/WqyJh/consul-vault-conf/test"
	capi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/require"
)

type ConsulConfig struct {
	ConsulAddr    string
	ConsulToken   string
	ReadonlyToken string
}

func TestConsul(t *testing.T) {
	ctx := context.Background()

	expected := `
Test:
  Hello: World
  Encrypted: ENC~b2/w1Q5OzFI3RdVK28dntMc5gUoIJ2TKZMLf0GfrIOBYjFcPTWh7EAukti0bUQ==
  Encrypted2: SEC~kv/unittest/encrypted/key1
  Encrypted3: SEC~kv/unittest/encrypted/key2
  Encrypted4: SEC~kv/unittest/encrypted2/key1`
	expected2 := `
Test:
  Key: CON~kv/unittest/config.yaml
  Plain: Hello World
`
	consulServer, err := test.SetupConsulServer(ctx, test.ConsulConfig{
		AclPolicies: []*capi.ACLPolicy{
			{
				Name: "unittest-read",
				Rules: `key_prefix "unittest/" {
	policy = "read"
}`,
			},
		},
		AclTokens: []*capi.ACLToken{
			{
				Description: "unittest-token",
				Policies: []*capi.ACLTokenPolicyLink{
					{
						Name: "unittest-read",
					},
				},
			},
		},
		KvPairs: []*capi.KVPair{
			{
				Key:   "unittest/config.yaml",
				Value: []byte(expected),
			},
			{
				Key:   "unittest/config2.yaml",
				Value: []byte(expected2),
			},
		},
	})
	require.NoError(t, err)
	defer consulServer.Stop()

	vaultServer, err := test.SetupVaultServer(ctx, test.VaultConfig{
		Policies: []test.VaultPolicy{
			{
				Name: "unittest-read",
				Policy: schema.PoliciesWriteAclPolicyRequest{
					Policy: `path "kv/data/unittest/*" {
						policy = "read"
					}`,
				},
			},
		},
		AppRoles: []test.VaultAppRole{
			{
				Name: "unittest",
				TokenRules: schema.AppRoleWriteRoleRequest{
					TokenPolicies: []string{"unittest-read"},
				},
			},
		},
		Pairs: []test.VaultPair{
			{
				MountPath: "kv",
				Key:       "unittest/encrypted",
				Value: schema.KvV2WriteRequest{
					Data: map[string]interface{}{
						"key1": "value1",
						"key2": "value2",
					},
				},
			},
			{
				MountPath: "kv",
				Key:       "unittest/encrypted2",
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
			},
		},
	})
	require.NoError(t, err)
	defer vaultServer.Stop()

	role := vaultServer.AppRoleTokens["unittest"]
	os.Setenv("CONSUL_ADDR", consulServer.ConsulAddr)
	os.Setenv("CONSUL_TOKEN", consulServer.RootToken)
	os.Setenv("VAULT_ADDR", vaultServer.VaultAddr)
	os.Setenv("VAULT_ROLE_ID", role.RoleId)
	os.Setenv("VAULT_SECRET_ID", role.SecretId)

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

	content, err = confz.ConsulGet("unittest/config2.yaml")
	require.NoError(t, err)
	require.Equal(t, expected2, string(content))

	type Test2 struct {
		Key   string
		Plain string
	}

	c2 := Test2{
		Key:   "CON~kv/unittest/config.yaml",
		Plain: "Hello World",
	}

	result, err = confz.Decrypt(c2)
	require.NoError(t, err)
	decrypted2 := result.(Test2)
	require.Equal(t, "Hello World", decrypted2.Plain)
	require.Equal(t, expected, decrypted2.Key)
}
