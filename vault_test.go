package confz_test

import (
	"context"
	"os"
	"testing"

	confz "github.com/WqyJh/consul-vault-conf"
	"github.com/WqyJh/consul-vault-conf/test"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/require"
)

type VaultConfig struct {
	VaultAddr      string
	VaultRootToken string
	VaultRoleId    string
	VaultSecretId  string
}

type VaultPair struct {
	Key   string
	Value schema.KvV2WriteRequest
	Meta  *schema.KvV2WriteMetadataRequest
}

type Conf struct {
	Hello      string
	Encrypted  string
	Encrypted2 string
	Encrypted3 string
	Encrypted4 string
}

func TestVault(t *testing.T) {
	ctx := context.Background()

	vaultContainer, err := test.SetupVaultServer(ctx, test.VaultConfig{
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
	defer vaultContainer.Stop()

	c := Conf{
		Hello:      "World",
		Encrypted:  "ENC~b2/w1Q5OzFI3RdVK28dntMc5gUoIJ2TKZMLf0GfrIOBYjFcPTWh7EAukti0bUQ==",
		Encrypted2: "SEC~kv/unittest/encrypted/key1",
		Encrypted3: "SEC~kv/unittest/encrypted/key2",
		Encrypted4: "SEC~kv/unittest/encrypted2/key1",
	}

	role := vaultContainer.AppRoleTokens["unittest"]
	vaultClient, err := confz.NewAppRoleVaultClient(
		vaultContainer.VaultAddr,
		role.RoleId,
		role.SecretId,
	)
	require.NoError(t, err)

	vaultSecretFetcher := confz.NewVaultSecretFetcher(vaultClient)
	encDecoder := confz.NewDefaultEncDecoder()
	decoded, err := confz.Decode(&c, vaultSecretFetcher, encDecoder)
	require.NoError(t, err)
	decodedConf := decoded.(*Conf)

	require.Equal(t, "World", decodedConf.Hello)
	require.Equal(t, "hello world hahaha", decodedConf.Encrypted)
	require.Equal(t, "value1", decodedConf.Encrypted2)
	require.Equal(t, "value2", decodedConf.Encrypted3)
	exists, err := confz.FileExists(decodedConf.Encrypted4)
	require.NoError(t, err)
	require.True(t, exists)
	content, err := os.ReadFile(decodedConf.Encrypted4)
	require.NoError(t, err)
	require.Equal(t, `value3`, string(content))

	t.Logf("conf: %+v", c)
	t.Logf("decoded: %+v", decodedConf)
}
