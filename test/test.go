package test

import (
	"context"
	"fmt"

	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	capi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/consul"
	vaultcontainer "github.com/testcontainers/testcontainers-go/modules/vault"
)

type ConsulServer struct {
	ConsulAddr string
	RootToken  string
	Tokens     map[string]string
	Container  testcontainers.Container
}

type ConsulConfig struct {
	AclPolicies []*capi.ACLPolicy
	AclTokens   []*capi.ACLToken
	KvPairs     []*capi.KVPair
}

func SetupConsulServer(ctx context.Context, config ConsulConfig) (*ConsulServer, error) {
	rootToken := uuid.New().String()
	serverConfig := fmt.Sprintf(`{
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
	consulContainer, err := consul.Run(ctx, "hashicorp/consul:1.20.1", consul.WithConfigString(serverConfig))
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %s", err)
	}

	consulAddr, err := consulContainer.PortEndpoint(ctx, nat.Port("8500"), "http")
	if err != nil {
		return nil, fmt.Errorf("failed to get consul address: %s", err)
	}

	client, err := capi.NewClient(&capi.Config{
		Address: consulAddr,
		Token:   rootToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %s", err)
	}

	acl := client.ACL()
	for _, policy := range config.AclPolicies {
		_, _, err = acl.PolicyCreate(policy, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create acl policy: %s", err)
		}
	}

	tokens := make(map[string]string)
	for _, token := range config.AclTokens {
		token, _, err := acl.TokenCreate(token, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create acl token: %s", err)
		}
		tokens[token.Description] = token.SecretID
	}

	for _, kv := range config.KvPairs {
		_, err = client.KV().Put(kv, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to put kv pair: %s", err)
		}
	}

	return &ConsulServer{
		ConsulAddr: consulAddr,
		RootToken:  rootToken,
		Tokens:     tokens,
		Container:  consulContainer,
	}, nil
}

func (s *ConsulServer) Stop() error {
	return s.Container.Terminate(context.Background())
}

type VaultServer struct {
	VaultAddr     string
	RootToken     string
	AppRoleTokens map[string]VaultAppRoleToken
	Container     testcontainers.Container
}

type VaultAppRoleToken struct {
	RoleId   string
	SecretId string
}

type VaultConfig struct {
	Policies []VaultPolicy
	AppRoles []VaultAppRole
	Pairs    []VaultPair
}

type VaultPolicy struct {
	Name   string
	Policy schema.PoliciesWriteAclPolicyRequest
}

type VaultAppRole struct {
	Name       string
	TokenRules schema.AppRoleWriteRoleRequest
}

type VaultPair struct {
	MountPath string
	Key       string
	Value     schema.KvV2WriteRequest
	Meta      *schema.KvV2WriteMetadataRequest
}

func SetupVaultServer(ctx context.Context, config VaultConfig) (*VaultServer, error) {
	rootToken := uuid.New().String()
	vaultContainer, err := vaultcontainer.Run(ctx, "hashicorp/vault:1.18.1", vaultcontainer.WithToken(rootToken), vaultcontainer.WithInitCommand(
		"auth enable approle",
		"secrets disable secret",
		"secrets enable -path kv -version=2 kv",
	))
	if err != nil {
		return nil, fmt.Errorf("failed to start vault container: %s", err)
	}

	vaultAddr, err := vaultContainer.PortEndpoint(ctx, nat.Port("8200"), "http")
	if err != nil {
		return nil, fmt.Errorf("failed to get vault address: %s", err)
	}

	client, err := vault.New(vault.WithAddress(vaultAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %s", err)
	}

	err = client.SetToken(rootToken)
	if err != nil {
		return nil, fmt.Errorf("failed to set vault token: %s", err)
	}

	appRoleTokens := make(map[string]VaultAppRoleToken)

	for _, policy := range config.Policies {
		_, err = client.System.PoliciesWriteAclPolicy(ctx, policy.Name, policy.Policy)
		if err != nil {
			return nil, fmt.Errorf("failed to create acl policy: %s", err)
		}
	}

	for _, appRole := range config.AppRoles {
		_, err = client.Auth.AppRoleWriteRole(ctx, appRole.Name, appRole.TokenRules)
		if err != nil {
			return nil, fmt.Errorf("failed to create app role: %s", err)
		}
		roleId, err := client.Auth.AppRoleReadRoleId(ctx, appRole.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to read app role id: %s", err)
		}
		secretId, err := client.Auth.AppRoleWriteSecretId(ctx, appRole.Name, schema.AppRoleWriteSecretIdRequest{})
		if err != nil {
			return nil, fmt.Errorf("failed to write app role secret id: %s", err)
		}
		appRoleTokens[appRole.Name] = VaultAppRoleToken{
			RoleId:   roleId.Data.RoleId,
			SecretId: secretId.Data.SecretId,
		}
	}

	for _, pair := range config.Pairs {
		_, err = client.Secrets.KvV2Write(ctx, pair.Key, pair.Value, vault.WithMountPath(pair.MountPath))
		if err != nil {
			return nil, fmt.Errorf("failed to write kv pair: %s", err)
		}

		if pair.Meta != nil {
			_, err = client.Secrets.KvV2WriteMetadata(ctx, pair.Key, *pair.Meta, vault.WithMountPath(pair.MountPath))
			if err != nil {
				return nil, fmt.Errorf("failed to write kv pair metadata: %s", err)
			}
		}
	}

	return &VaultServer{
		VaultAddr:     vaultAddr,
		RootToken:     rootToken,
		AppRoleTokens: appRoleTokens,
		Container:     vaultContainer,
	}, nil
}

func (s *VaultServer) Stop() error {
	return s.Container.Terminate(context.Background())
}
