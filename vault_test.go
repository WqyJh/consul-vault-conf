package confz_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	confz "github.com/WqyJh/consul-vault-conf"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	vaultcontainer "github.com/testcontainers/testcontainers-go/modules/vault"
	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/logx"
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
	data := `Hello: World
Encrypted: ENC~b2/w1Q5OzFI3RdVK28dntMc5gUoIJ2TKZMLf0GfrIOBYjFcPTWh7EAukti0bUQ==
Encrypted2: SEC~kv/unittest/encrypted/key1
Encrypted3: SEC~kv/unittest/encrypted/key2
Encrypted4: SEC~kv/unittest/encrypted2/key1`

	ctx := context.Background()
	vaultContainer, rootToken, err := setupVaultContainer(ctx)
	require.NoError(t, err)
	defer testcontainers.TerminateContainer(vaultContainer)

	vaultConfig := bootstrapVault(t, vaultContainer, rootToken, VaultPair{
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

	logx.Infow("vaultConfig", logx.Field("vaultConfig", vaultConfig))

	var c Conf
	err = conf.LoadConfigFromYamlBytes([]byte(data), &c)
	require.NoError(t, err)

	vaultClient, err := confz.NewAppRoleVaultClient(
		vaultConfig.VaultAddr,
		vaultConfig.VaultRoleId,
		vaultConfig.VaultSecretId,
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

	logx.Infow("conf", logx.Field("conf", c), logx.Field("decoded", decodedConf))
}

func setupVaultContainer(ctx context.Context) (testcontainers.Container, string, error) {
	vaultRootToken := uuid.New().String()
	vaultContainer, err := vaultcontainer.Run(ctx, "hashicorp/vault:1.18.1", vaultcontainer.WithToken(vaultRootToken), vaultcontainer.WithInitCommand(
		"auth enable approle",
		"secrets disable secret",
		"secrets enable -path kv -version=2 kv",
	))
	if err != nil {
		return nil, "", fmt.Errorf("failed to start vault container: %s", err)
	}
	return vaultContainer, vaultRootToken, nil
}

func bootstrapVault(t *testing.T, container testcontainers.Container, rootToken string, pairs ...VaultPair) VaultConfig {
	ctx := context.Background()
	vaultAddr, err := container.PortEndpoint(ctx, nat.Port("8200"), "http")
	require.NoError(t, err)

	client, err := vault.New(vault.WithAddress(vaultAddr))
	require.NoError(t, err)

	err = client.SetToken(rootToken)
	require.NoError(t, err)

	_, err = client.System.PoliciesWriteAclPolicy(ctx, "unittest-read", schema.PoliciesWriteAclPolicyRequest{
		Policy: `path "kv/data/unittest/*" {
			policy = "read"
		}`,
	})
	require.NoError(t, err)

	_, err = client.Auth.AppRoleWriteRole(ctx, "unittest", schema.AppRoleWriteRoleRequest{
		TokenPolicies: []string{"unittest-read"},
	})
	require.NoError(t, err)

	roleId, err := client.Auth.AppRoleReadRoleId(ctx, "unittest")
	require.NoError(t, err)

	secretId, err := client.Auth.AppRoleWriteSecretId(ctx, "unittest", schema.AppRoleWriteSecretIdRequest{})
	require.NoError(t, err)

	for _, pair := range pairs {
		_, err = client.Secrets.KvV2Write(ctx, pair.Key, pair.Value, vault.WithMountPath("kv"))
		require.NoError(t, err)

		if pair.Meta != nil {
			_, err = client.Secrets.KvV2WriteMetadata(ctx, pair.Key, *pair.Meta, vault.WithMountPath("kv"))
			require.NoError(t, err)
		}
	}

	return VaultConfig{
		VaultAddr:      vaultAddr,
		VaultRootToken: rootToken,
		VaultRoleId:    roleId.Data.RoleId,
		VaultSecretId:  secretId.Data.SecretId,
	}
}
