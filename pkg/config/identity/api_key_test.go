package identity

import (
	"context"
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"gotest.tools/assert"
)

var (
	getCredentialsFromReq func() (string, error)

	clusterSecret1 = v1.Secret{Data: map[string][]byte{"api_key": []byte("ObiWanKenobiLightSaber")}}
	clusterSecret2 = v1.Secret{Data: map[string][]byte{"api_key": []byte("MasterYodaLightSaber")}}

	listSecretsFunc = func(list *v1.SecretList) error {
		var secrets []v1.Secret
		secrets = append(secrets, clusterSecret1, clusterSecret2)
		list.Items = append(list.Items, secrets...)
		return nil
	}
)

// TODO: Replace for a Mock Factory these kind of interfaces.
type AuthContextMock struct{}

func (_m *AuthContextMock) GetAPI() interface{} {
	return nil
}

func (_m *AuthContextMock) GetResolvedIdentity() (interface{}, interface{}) {
	return nil, nil
}

func (_m *AuthContextMock) GetResolvedMetadata() map[interface{}]interface{} {
	return nil
}

func (_m *AuthContextMock) GetParentContext() *context.Context {
	return nil
}

func (_m *AuthContextMock) GetRequest() *envoyServiceAuthV3.CheckRequest {
	return nil
}

func (_m *AuthContextMock) GetHttp() *envoyServiceAuthV3.AttributeContext_HttpRequest {
	return nil
}

type authCredMock struct{}

func (a *authCredMock) GetCredentialsFromReq(*envoyServiceAuthV3.AttributeContext_HttpRequest) (string, error) {
	return getCredentialsFromReq()
}

type MockK8sClient struct{}

func (k *MockK8sClient) Get(_ context.Context, _ client.ObjectKey, _ runtime.Object) error {
	return nil
}

func (k *MockK8sClient) List(_ context.Context, list runtime.Object, _ ...client.ListOption) error {
	return listSecretsFunc(list.(*v1.SecretList))
}

func TestConstants(t *testing.T) {
	assert.Check(t, "api_key" == apiKeySelector)
	assert.Check(t, "the API Key provided is invalid" == invalidApiKeyMsg)
	assert.Check(t, "no API Keys were found on the request" == noApiKeysFoundMsg)
	assert.Check(t, "Successfully authenticated with the provided API key" == authSuccessfulMsg)
}

func TestNewApiKeyIdentity(t *testing.T) {
	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{}, &MockK8sClient{})

	assert.Check(t, apiKey.Name == "jedi")
	assert.Check(t, apiKey.LabelSelectors["planet"] == "tatooine")
	assert.Check(t, len(apiKey.authorizedCredentials) == 2)
	_, exists := apiKey.authorizedCredentials["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.authorizedCredentials["MasterYodaLightSaber"]
	assert.Check(t, exists)
}

func TestCallSuccess(t *testing.T) {
	getCredentialsFromReq = func() (string, error) {
		return "ObiWanKenobiLightSaber", nil
	}

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{}, &MockK8sClient{})
	auth, err := apiKey.Call(&AuthContextMock{}, context.TODO())

	assert.NilError(t, err)
	assert.Check(t, string(auth.(v1.Secret).Data["api_key"]) == "ObiWanKenobiLightSaber")
}

func TestCallNoApiKeyFail(t *testing.T) {
	getCredentialsFromReq = func() (string, error) {
		return "", fmt.Errorf("something went wrong getting the API Key")
	}

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{}, &MockK8sClient{})

	_, err := apiKey.Call(&AuthContextMock{}, context.TODO())

	assert.Error(t, err, "something went wrong getting the API Key")

}

func TestCallInvalidApiKeyFail(t *testing.T) {
	getCredentialsFromReq = func() (string, error) {
		return "ASithLightSaber", nil
	}

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{}, &MockK8sClient{})
	_, err := apiKey.Call(&AuthContextMock{}, context.TODO())

	assert.Error(t, err, "the API Key provided is invalid")
}

func TestGetCredentialsFromClusterSuccess(t *testing.T) {
	apiKey := NewApiKeyIdentity("X-API-KEY", map[string]string{"planet": "tatooine"}, &authCredMock{}, &MockK8sClient{})
	err := apiKey.GetCredentialsFromCluster(context.TODO())

	assert.NilError(t, err)
	assert.Check(t, len(apiKey.authorizedCredentials) == 2)

	secret1, exists := apiKey.authorizedCredentials["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	assert.Check(t, secret1.String() == clusterSecret1.String())

	secret2, exists := apiKey.authorizedCredentials["MasterYodaLightSaber"]
	assert.Check(t, exists)
	assert.Check(t, secret2.String() == clusterSecret2.String())
}

func TestGetCredentialsFromClusterFail(t *testing.T) {
	listSecretsFunc = func(list *v1.SecretList) error {
		return fmt.Errorf("something terribly wrong happened")
	}
	apiKey := NewApiKeyIdentity("X-API-KEY", map[string]string{"planet": "tatooine"}, &authCredMock{}, &MockK8sClient{})
	err := apiKey.GetCredentialsFromCluster(context.TODO())

	assert.Error(t, err, "something terribly wrong happened")
}
