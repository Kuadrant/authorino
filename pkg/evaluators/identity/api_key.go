package identity

import (
	"context"
	"fmt"
	"sync"

	"github.com/samber/lo"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/log"

	k8s "k8s.io/api/core/v1"
	k8s_labels "k8s.io/apimachinery/pkg/labels"
	k8s_types "k8s.io/apimachinery/pkg/types"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultAPIKeySelector       = "api_key"
	invalidApiKeyMsg            = "the API Key provided is invalid"
	credentialsFetchingErrorMsg = "Something went wrong fetching the authorized credentials"
)

type APIKey struct {
	auth.AuthCredentials

	Name           string              `yaml:"name"`
	LabelSelectors k8s_labels.Selector `yaml:"labelSelectors"`
	Namespace      string              `yaml:"namespace"`
	KeySelectors   []string            `yaml:"keySelectors"`

	// Map of API Key value to secret
	secrets   map[string]k8s.Secret
	mutex     sync.RWMutex
	k8sClient k8s_client.Reader
}

func NewApiKeyIdentity(name string, labelSelectors k8s_labels.Selector, namespace string, keySelectors []string, authCred auth.AuthCredentials, k8sClient k8s_client.Reader, ctx context.Context) *APIKey {
	if len(keySelectors) == 0 {
		keySelectors = append(keySelectors, defaultAPIKeySelector)
	}
	apiKey := &APIKey{
		AuthCredentials: authCred,
		Name:            name,
		LabelSelectors:  labelSelectors,
		Namespace:       namespace,
		KeySelectors:    keySelectors,
		secrets:         make(map[string]k8s.Secret),
		k8sClient:       k8sClient,
	}
	if err := apiKey.loadSecrets(context.TODO()); err != nil {
		log.FromContext(ctx).WithName("apikey").Error(err, credentialsFetchingErrorMsg)
	}
	return apiKey
}

// loadSecrets will load the matching k8s secrets from the cluster to the cache of trusted API keys
func (a *APIKey) loadSecrets(ctx context.Context) error {
	opts := []k8s_client.ListOption{k8s_client.MatchingLabelsSelector{Selector: a.LabelSelectors}}
	if namespace := a.Namespace; namespace != "" {
		opts = append(opts, k8s_client.InNamespace(namespace))
	}
	var secretList = &k8s.SecretList{}
	if err := a.k8sClient.List(ctx, secretList, opts...); err != nil {
		return err
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	for _, secret := range secretList.Items {
		a.appendK8sSecretBasedIdentity(secret)
	}

	return nil
}

// Call will evaluate the credentials within the request against the authorized ones
func (a *APIKey) Call(pipeline auth.AuthPipeline, _ context.Context) (interface{}, error) {
	if reqKey, err := a.GetCredentialsFromReq(pipeline.GetHttp()); err != nil {
		return nil, err
	} else {
		a.mutex.RLock()
		defer a.mutex.RUnlock()

		for key, secret := range a.secrets {
			if key == reqKey {
				return secret, nil
			}
		}
	}
	err := fmt.Errorf(invalidApiKeyMsg)
	return nil, err
}

// impl:K8sSecretBasedIdentityConfigEvaluator

func (a *APIKey) GetK8sSecretLabelSelectors() k8s_labels.Selector {
	return a.LabelSelectors
}

func (a *APIKey) AddK8sSecretBasedIdentity(ctx context.Context, new k8s.Secret) {
	if !a.withinScope(new.GetNamespace()) {
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	logger := log.FromContext(ctx).WithName("apikey")

	// Get all current keys in the map that match the new secret name and namespace
	currentKeysSecret := lo.PickBy(a.secrets, func(key string, current k8s.Secret) bool {
		return current.GetNamespace() == new.GetNamespace() && current.GetName() == new.GetName()
	})

	// get api keys from new secret
	newAPIKeys := a.getValuesFromSecret(new)

	for _, newKey := range newAPIKeys {
		a.secrets[newKey] = new
		if _, ok := currentKeysSecret[newKey]; !ok {
			logger.V(1).Info("api key added")
		} else {
			logger.V(1).Info("api key secret updated")
		}
	}

	// get difference between new and the old
	staleKeys, _ := lo.Difference(lo.Keys(currentKeysSecret), newAPIKeys)
	for _, newKey := range staleKeys {
		delete(a.secrets, newKey)
		logger.V(1).Info("stale api key deleted")
	}
}

func (a *APIKey) RevokeK8sSecretBasedIdentity(ctx context.Context, deleted k8s_types.NamespacedName) {
	if !a.withinScope(deleted.Namespace) {
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	for key, secret := range a.secrets {
		if secret.GetNamespace() == deleted.Namespace && secret.GetName() == deleted.Name {
			delete(a.secrets, key)
			log.FromContext(ctx).WithName("apikey").V(1).Info("api key deleted")
		}
	}
}

func (a *APIKey) withinScope(namespace string) bool {
	return a.Namespace == "" || a.Namespace == namespace
}

// Appends the K8s Secret to the cache of API keys
// Caution! This function is not thread-safe. Make sure to acquire a lock before calling it.
func (a *APIKey) appendK8sSecretBasedIdentity(secret k8s.Secret) bool {
	values := a.getValuesFromSecret(secret)
	for _, value := range values {
		a.secrets[value] = secret
	}

	// Was appended if length is greater than zero
	return len(values) != 0
}

// getValuesFromSecret extracts the values from the secret based on APIKey KeySelectors
func (a *APIKey) getValuesFromSecret(secret k8s.Secret) []string {
	var keys []string
	for _, key := range a.KeySelectors {
		value, isAPIKeySecret := secret.Data[key]

		if isAPIKeySecret && len(value) > 0 {
			keys = append(keys, string(value))
		}
	}

	return keys
}
