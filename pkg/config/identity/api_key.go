package identity

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	apiKeySelector              = "api_key"
	invalidApiKeyMsg            = "the API Key provided is invalid"
	noApiKeysFoundMsg           = "no API Keys were found on the request"
	authSuccessfulMsg           = "Successfully authenticated with the provided API key"
	credentialsFetchingErrorMsg = "Something went wrong fetching the authorized credentials"
)

// APIKeyIdentityEvaluator interface represents the API Key Identity evaluator
type APIKeyIdentityEvaluator interface {
	GetCredentialsFromCluster(context.Context) error
	Call(common.AuthContext, context.Context) (interface{}, error)
}

type apiKeyDetails struct {
	Name                  string            `yaml:"name"`
	LabelSelectors        map[string]string `yaml:"label_selectors"`
	k8sClient             client.Reader
	authorizedCredentials map[string]v1.Secret
}

// APIKey struct implements the APIKeyIdentityEvaluator interface
type APIKey struct {
	auth_credentials.AuthCredentials
	apiKeyDetails
}

var (
	apiKeyLog = ctrl.Log.WithName("Authorino").WithName("ApiKey")
)

// NewApiKeyIdentity creates a new instance of APIKey
func NewApiKeyIdentity(name string, labelSelectors map[string]string, authCred auth_credentials.AuthCredentials, k8sClient client.Reader) *APIKey {
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
		apiKeyLog.Error(err, credentialsFetchingErrorMsg)
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
func (apiKey *APIKey) Call(authCtx common.AuthContext, _ context.Context) (interface{}, error) {
	if reqKey, err := apiKey.GetCredentialsFromReq(authCtx.GetHttp()); err != nil {
		apiKeyLog.Error(err, noApiKeysFoundMsg)
		return nil, err
	} else {
		for key, secret := range apiKey.authorizedCredentials {
			if key == reqKey {
				apiKeyLog.Info(authSuccessfulMsg, "secret", secret)
				return secret, nil
			}
		}
	}
	err := fmt.Errorf(invalidApiKeyMsg)
	apiKeyLog.Error(err, invalidApiKeyMsg)
	return nil, err
}
