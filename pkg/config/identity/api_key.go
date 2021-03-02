package identity

import (
	"context"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	invalidApiKeyMsg  = "the API Key provided is invalid"
	noApiKeysFoundMsg = "no API Keys were found on the request"
	authSuccessfulMsg = "Successfully authenticated with the provided API key"
)

type apiKeyDetails struct {
	Name                  string            `yaml:"name"`
	LabelSelectors        map[string]string `yaml:"label_selectors"`
	authorizedCredentials []string
}

type APIKey struct {
	auth_credentials.AuthCredentials
	apiKeyDetails
}

var (
	apiKeyLog = ctrl.Log.WithName("Authorino").WithName("ApiKey")
)

func NewApiKeyIdentity(name string, labelSelectors map[string]string, authCred auth_credentials.AuthCredentials) (*APIKey, error) {
	if credentials, err := authCred.GetCredentialsFromCluster(context.TODO(), labelSelectors); err != nil {
		return nil, err
	} else {
		return &APIKey{
			authCred,
			apiKeyDetails{
				name,
				labelSelectors,
				credentials,
			},
		}, nil
	}
}

func (apiKey *APIKey) Call(authCtx common.AuthContext, _ context.Context) (interface{}, error) {
	if reqKey, err := apiKey.GetCredentialsFromReq(authCtx.GetHttp()); err != nil {
		apiKeyLog.Error(err, noApiKeysFoundMsg)
		return nil, err
	} else {
		for _, secret := range apiKey.authorizedCredentials {
			if secret == reqKey {
				return authSuccessfulMsg, nil
			}
		}
	}
	err := fmt.Errorf(invalidApiKeyMsg)
	apiKeyLog.Error(err, invalidApiKeyMsg)
	return nil, err
}
