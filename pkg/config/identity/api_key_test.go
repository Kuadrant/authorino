package identity

import (
	"context"
	"fmt"
	"testing"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"gotest.tools/assert"
)

var (
	getCredentialsFromReq     func() (string, error)
	getCredentialsFromCluster func() ([]string, error)
)

// TODO: Replace for a Mock Factory these kind of interfaces.
type AuthContextMock struct{}

func (_m *AuthContextMock) FindIdentityByName(_ string) (interface{}, error) {
	return nil, nil
}

func (_m *AuthContextMock) GetAPI() interface{} {
	return nil
}

func (_m *AuthContextMock) GetIdentity() interface{} {
	return nil
}

func (_m *AuthContextMock) GetMetadata() map[string]interface{} {
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
func (a *authCredMock) GetCredentialsFromCluster(context.Context, map[string]string) ([]string, error) {
	return getCredentialsFromCluster()
}

func TestConstants(t *testing.T) {
	assert.Check(t, "the API Key provided is invalid" == invalidApiKeyMsg)
	assert.Check(t, "no API Keys were found on the request" == noApiKeysFoundMsg)
	assert.Check(t, "Successfully authenticated with the provided API key" == authSuccessfulMsg)
}

func TestNewApiKeyIdentitySuccess(t *testing.T) {
	getCredentialsFromCluster = func() ([]string, error) {
		return []string{"ObiWanKenobiLightSaber", "R2D2Probe"}, nil
	}
	apiKey, err := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{})
	assert.NilError(t, err)
	assert.Check(t, apiKey.Name == "jedi")
	assert.Check(t, apiKey.LabelSelectors["planet"] == "tatooine")
	assert.Check(t, len(apiKey.authorizedCredentials) == 2)
	assert.Check(t, apiKey.authorizedCredentials[0] == "ObiWanKenobiLightSaber")
	assert.Check(t, apiKey.authorizedCredentials[1] == "R2D2Probe")
}

func TestNewApiKeyIdentityFail(t *testing.T) {
	getCredentialsFromCluster = func() ([]string, error) {
		return nil, fmt.Errorf("the empire strikes back")
	}
	_, err := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{})
	assert.Error(t, err, "the empire strikes back")
}

func TestCallSuccess(t *testing.T) {
	getCredentialsFromCluster = func() ([]string, error) {
		return []string{"ObiWanKenobiLightSaber", "R2D2Probe"}, nil
	}

	getCredentialsFromReq = func() (string, error) {
		return "ObiWanKenobiLightSaber", nil
	}

	apiKey, err := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{})
	if err == nil {
		auth, err := apiKey.Call(&AuthContextMock{}, context.TODO())

		assert.NilError(t, err)
		assert.Check(t, auth == "Successfully authenticated with the provided API key")
	}
}

func TestCallNoApiKeyFail(t *testing.T) {
	getCredentialsFromCluster = func() ([]string, error) {
		return []string{"ObiWanKenobiLightSaber", "R2D2Probe"}, nil
	}

	getCredentialsFromReq = func() (string, error) {
		return "", fmt.Errorf("something went wrong getting the API Key")
	}

	apiKey, err := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{})

	if err == nil {
		_, err := apiKey.Call(&AuthContextMock{}, context.TODO())

		assert.Error(t, err, "something went wrong getting the API Key")
	}
}

func TestCallInvalidApiKeyFail(t *testing.T) {
	getCredentialsFromCluster = func() ([]string, error) {
		return []string{"ObiWanKenobiLightSaber", "R2D2Probe"}, nil
	}

	getCredentialsFromReq = func() (string, error) {
		return "ASithLightSaber", nil
	}

	apiKey, err := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, &authCredMock{})

	if err == nil {
		_, err := apiKey.Call(&AuthContextMock{}, context.TODO())

		assert.Error(t, err, "the API Key provided is invalid")
	}
}
