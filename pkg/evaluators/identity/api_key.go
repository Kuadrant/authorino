package identity

import (
	"context"
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/log"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	apiKeySelector              = "api_key"
	invalidApiKeyMsg            = "the API Key provided is invalid"
	credentialsFetchingErrorMsg = "Something went wrong fetching the authorized credentials"
)

type APIKey struct {
	auth.AuthCredentials

	Name           string            `yaml:"name"`
	LabelSelectors map[string]string `yaml:"labelSelectors"`
	Namespace      string            `yaml:"namespace"`

	secrets   map[string]v1.Secret
	mutex     sync.Mutex
	k8sClient client.Reader
}

// NewApiKeyIdentity creates a new instance of APIKey
func NewApiKeyIdentity(name string, labelSelectors map[string]string, namespace string, authCred auth.AuthCredentials, k8sClient client.Reader, ctx context.Context) *APIKey {
	apiKey := &APIKey{
		AuthCredentials: authCred,
		Name:            name,
		LabelSelectors:  labelSelectors,
		Namespace:       namespace,
		k8sClient:       k8sClient,
	}
	if err := apiKey.loadSecrets(context.TODO()); err != nil {
		log.FromContext(ctx).WithName("apikey").Error(err, credentialsFetchingErrorMsg)
	}
	return apiKey
}

// loadSecrets will get the k8s secrets and update the APIKey instance
func (apiKey *APIKey) loadSecrets(ctx context.Context) error {
	opts := []client.ListOption{client.MatchingLabels(apiKey.LabelSelectors)}
	if namespace := apiKey.Namespace; namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	var secretList = &v1.SecretList{}
	if err := apiKey.k8sClient.List(ctx, secretList, opts...); err != nil {
		return err
	}
	var secrets = make(map[string]v1.Secret)
	for _, secret := range secretList.Items {
		secrets[string(secret.Data[apiKeySelector])] = secret
	}
	apiKey.secrets = secrets
	return nil
}

// Call will evaluate the credentials within the request against the authorized ones
func (apiKey *APIKey) Call(pipeline auth.AuthPipeline, _ context.Context) (interface{}, error) {
	if reqKey, err := apiKey.GetCredentialsFromReq(pipeline.GetHttp()); err != nil {
		return nil, err
	} else {
		for key, secret := range apiKey.secrets {
			if key == reqKey {
				return secret, nil
			}
		}
	}
	err := fmt.Errorf(invalidApiKeyMsg)
	return nil, err
}

// impl:APIKeyIdentityConfigEvaluator

func (apiKey *APIKey) GetAPIKeyLabelSelectors() map[string]string {
	return apiKey.LabelSelectors
}

func (apiKey *APIKey) RefreshAPIKeySecret(ctx context.Context, new v1.Secret) {
	if !apiKey.withinScope(new.GetNamespace()) {
		return
	}

	logger := log.FromContext(ctx).WithName("apikey")

	apiKey.mutex.Lock()
	defer apiKey.mutex.Unlock()

	newAPIKeyValue := string(new.Data[apiKeySelector])
	newAIKeyName := fmt.Sprintf("%s/%s", new.GetNamespace(), new.GetName())

	// updating existing
	for _, current := range apiKey.secrets {
		if current.GetNamespace() == new.GetNamespace() && current.GetName() == new.GetName() {
			oldAPIKeyValue := string(current.Data[apiKeySelector])
			if oldAPIKeyValue != newAPIKeyValue {
				apiKey.secrets[newAPIKeyValue] = new
				delete(apiKey.secrets, oldAPIKeyValue)
				logger.V(1).Info("api key updated", "authconfig", newAIKeyName)
			} else {
				logger.V(1).Info("api key unchanged", "authconfig", newAIKeyName)
			}
			return
		}
	}

	apiKey.secrets[newAPIKeyValue] = new
	logger.V(1).Info("api key added", "authconfig", newAIKeyName)
}

func (apiKey *APIKey) DeleteAPIKeySecret(ctx context.Context, deleted types.NamespacedName) {
	if !apiKey.withinScope(deleted.Namespace) {
		return
	}

	apiKey.mutex.Lock()
	defer apiKey.mutex.Unlock()

	for key, secret := range apiKey.secrets {
		if secret.GetNamespace() == deleted.Namespace && secret.GetName() == deleted.Name {
			delete(apiKey.secrets, key)
			log.FromContext(ctx).WithName("apikey").V(1).Info("api key deleted", "authconfig", fmt.Sprintf("%s/%s", deleted.Namespace, deleted.Name))
			return
		}
	}
}

func (apiKey *APIKey) withinScope(namespace string) bool {
	return apiKey.Namespace == "" || apiKey.Namespace == namespace
}
