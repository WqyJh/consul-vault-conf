package zero_test

import (
	"context"
	"os"
	"testing"

	confz "github.com/WqyJh/consul-vault-conf"
	"github.com/WqyJh/consul-vault-conf/adapter/zero"
	"github.com/WqyJh/consul-vault-conf/test"
	capi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/require"
)

type Conf struct {
	Hello      string
	Encrypted  string
	Encrypted2 string
	Encrypted3 string
	Encrypted4 string
}

func TestZero(t *testing.T) {
	ctx := context.Background()

	expected := `
Test:
  Hello: World
  Encrypted: ENC~b2/w1Q5OzFI3RdVK28dntMc5gUoIJ2TKZMLf0GfrIOBYjFcPTWh7EAukti0bUQ==
  Encrypted2: SEC~kv/unittest/encrypted/key1
  Encrypted3: SEC~kv/unittest/encrypted/key2
  Encrypted4: SEC~kv/unittest/encrypted2/key1`
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

	type Test struct {
		Test Conf
	}

	c := zero.SecurityMustLoad[Test]("unittest/config.yaml")

	// check decrypted
	require.Equal(t, "World", c.Test.Hello)
	require.Equal(t, "value1", c.Test.Encrypted2)
	require.Equal(t, "value2", c.Test.Encrypted3)
	exists, err := confz.FileExists(c.Test.Encrypted4)
	require.NoError(t, err)
	require.True(t, exists)
	fileContent, err := os.ReadFile(c.Test.Encrypted4)
	require.NoError(t, err)
	require.Equal(t, `value3`, string(fileContent))
}
