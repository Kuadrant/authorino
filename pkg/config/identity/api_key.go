package identity

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	apiKeySelector              = "api_key"
	invalidApiKeyMsg            = "the API Key provided is invalid"
	credentialsFetchingErrorMsg = "Something went wrong fetching the authorized credentials"
)

type apiKeyDetails struct {
	Name                  string            `yaml:"name"`
	LabelSelectors        map[string]string `yaml:"labelSelectors"`
	k8sClient             client.Reader
	authorizedCredentials map[string]v1.Secret
}

type APIKey struct {
	auth_credentials.AuthCredentials

	apiKeyDetails
}

// NewApiKeyIdentity creates a new instance of APIKey
func NewApiKeyIdentity(name string, labelSelectors map[string]string, authCred auth_credentials.AuthCredentials, k8sClient client.Reader, ctx context.Context) *APIKey {
	apiKey := &APIKey{
		authCred,
		apiKeyDetails{
			name,
			labelSelectors,
			k8sClient,
			nil,
		},
	}
	if err := apiKey.GetCredentialsFromCluster(context.TODO()); err != nil {
		log.FromContext(ctx).WithName("apikey").Error(err, credentialsFetchingErrorMsg)
	}
	return apiKey
}

// GetCredentialsFromCluster will get the k8s secrets and update the APIKey instance
func (apiKey *APIKey) GetCredentialsFromCluster(ctx context.Context) error {
	var matchingLabels client.MatchingLabels = apiKey.LabelSelectors
	var secretList = &v1.SecretList{}
	if err := apiKey.k8sClient.List(ctx, secretList, matchingLabels); err != nil {
		return err
	}
	var parsedSecrets = make(map[string]v1.Secret)

	for _, secret := range secretList.Items {
		parsedSecrets[string(secret.Data[apiKeySelector])] = secret
	}
	apiKey.authorizedCredentials = parsedSecrets
	return nil
}

// Call will evaluate the credentials within the request against the authorized ones
func (apiKey *APIKey) Call(pipeline common.AuthPipeline, _ context.Context) (interface{}, error) {
	if reqKey, err := apiKey.GetCredentialsFromReq(pipeline.GetHttp()); err != nil {
		return nil, err
	} else {
		for key, secret := range apiKey.authorizedCredentials {
			if key == reqKey {
				return secret, nil
			}
		}
	}
	err := fmt.Errorf(invalidApiKeyMsg)
	return nil, err
}

func (apiKey *APIKey) FindSecretByName(lookup types.NamespacedName) *v1.Secret {
	for _, secret := range apiKey.authorizedCredentials {
		if secret.GetNamespace() == lookup.Namespace && secret.GetName() == lookup.Name {
			return &secret
		}
	}
	return nil
}
