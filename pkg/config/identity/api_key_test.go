package identity

import (
	"context"
	"fmt"
	"testing"

	. "github.com/kuadrant/authorino/pkg/common/auth_credentials/mocks"
	. "github.com/kuadrant/authorino/pkg/common/mocks"

	. "github.com/golang/mock/gomock"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"gotest.tools/assert"
)

var (
	clusterSecret1 = v1.Secret{Data: map[string][]byte{"api_key": []byte("ObiWanKenobiLightSaber")}}
	clusterSecret2 = v1.Secret{Data: map[string][]byte{"api_key": []byte("MasterYodaLightSaber")}}

	listSecretsFunc = func(list *v1.SecretList) error {
		var secrets []v1.Secret
		secrets = append(secrets, clusterSecret1, clusterSecret2)
		list.Items = append(list.Items, secrets...)
		return nil
	}
)

type MockK8sClient struct{}

func (k *MockK8sClient) Get(_ context.Context, _ client.ObjectKey, _ client.Object) error {
	return nil
}

func (k *MockK8sClient) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	return listSecretsFunc(list.(*v1.SecretList))
}

func mockAuthPipeline(ctrl *Controller) (pipelineMock *MockAuthPipeline) {
	pipelineMock = NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetHttp().Return(nil)
	return
}

func TestConstants(t *testing.T) {
	assert.Check(t, "api_key" == apiKeySelector)
	assert.Check(t, "the API Key provided is invalid" == invalidApiKeyMsg)
}

func TestNewApiKeyIdentity(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, NewMockAuthCredentials(ctrl), &MockK8sClient{}, context.TODO())

	assert.Check(t, apiKey.Name == "jedi")
	assert.Check(t, apiKey.LabelSelectors["planet"] == "tatooine")
	assert.Check(t, len(apiKey.authorizedCredentials) == 2)
	_, exists := apiKey.authorizedCredentials["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.authorizedCredentials["MasterYodaLightSaber"]
	assert.Check(t, exists)
}

func TestCallSuccess(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("ObiWanKenobiLightSaber", nil)

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, authCredMock, &MockK8sClient{}, context.TODO())
	auth, err := apiKey.Call(pipelineMock, context.TODO())

	assert.NilError(t, err)
	assert.Check(t, string(auth.(v1.Secret).Data["api_key"]) == "ObiWanKenobiLightSaber")
}

func TestCallNoApiKeyFail(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("", fmt.Errorf("something went wrong getting the API Key"))

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, authCredMock, &MockK8sClient{}, context.TODO())

	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "something went wrong getting the API Key")

}

func TestCallInvalidApiKeyFail(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("ASithLightSaber", nil)

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "tatooine"}, authCredMock, &MockK8sClient{}, context.TODO())
	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "the API Key provided is invalid")
}

func TestGetCredentialsFromClusterSuccess(t *testing.T) {
	apiKey := NewApiKeyIdentity("X-API-KEY", map[string]string{"planet": "tatooine"}, nil, &MockK8sClient{}, nil)

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
	apiKey := NewApiKeyIdentity("X-API-KEY", map[string]string{"planet": "tatooine"}, nil, &MockK8sClient{}, context.TODO())

	err := apiKey.GetCredentialsFromCluster(context.TODO())
	assert.Error(t, err, "something terribly wrong happened")
}
