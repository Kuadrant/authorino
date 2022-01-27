package identity

import (
	"context"
	"fmt"
	"testing"

	. "github.com/kuadrant/authorino/pkg/common/auth_credentials/mocks"
	. "github.com/kuadrant/authorino/pkg/common/mocks"

	. "github.com/golang/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"gotest.tools/assert"
)

var (
	apiKeySecret1 = &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "obi-wan", Namespace: "ns1", Labels: map[string]string{"planet": "coruscant"}}, Data: map[string][]byte{"api_key": []byte("ObiWanKenobiLightSaber")}}
	apiKeySecret2 = &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "yoda", Namespace: "ns2", Labels: map[string]string{"planet": "coruscant"}}, Data: map[string][]byte{"api_key": []byte("MasterYodaLightSaber")}}
	apiKeySecret3 = &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "anakin", Namespace: "ns2", Labels: map[string]string{"planet": "tatooine"}}, Data: map[string][]byte{"api_key": []byte("AnakinSkywalkerLightSaber")}}
	k8sClient     = mockAPIkeyK8sClient(apiKeySecret1, apiKeySecret2, apiKeySecret3)
)

func mockAPIkeyK8sClient(initObjs ...runtime.Object) client.WithWatch {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(initObjs...).Build()
}

func mockAuthPipeline(ctrl *Controller) (pipelineMock *MockAuthPipeline) {
	pipelineMock = NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetHttp().Return(nil)
	return
}

func TestConstants(t *testing.T) {
	assert.Equal(t, apiKeySelector, "api_key")
	assert.Equal(t, invalidApiKeyMsg, "the API Key provided is invalid")
}

func TestNewApiKeyIdentityAllNamespaces(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "coruscant"}, "", NewMockAuthCredentials(ctrl), k8sClient, context.TODO())

	assert.Equal(t, apiKey.Name, "jedi")
	assert.Equal(t, apiKey.LabelSelectors["planet"], "coruscant")
	assert.Equal(t, apiKey.Namespace, "")
	assert.Equal(t, len(apiKey.authorizedCredentials), 2)
	_, exists := apiKey.authorizedCredentials["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.authorizedCredentials["MasterYodaLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.authorizedCredentials["AnakinSkywalkerLightSaber"]
	assert.Check(t, !exists)
}

func TestNewApiKeyIdentitySingleNamespace(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "coruscant"}, "ns1", NewMockAuthCredentials(ctrl), k8sClient, context.TODO())

	assert.Equal(t, apiKey.Name, "jedi")
	assert.Equal(t, apiKey.LabelSelectors["planet"], "coruscant")
	assert.Equal(t, apiKey.Namespace, "ns1")
	assert.Equal(t, len(apiKey.authorizedCredentials), 1)
	_, exists := apiKey.authorizedCredentials["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.authorizedCredentials["MasterYodaLightSaber"]
	assert.Check(t, !exists)
	_, exists = apiKey.authorizedCredentials["AnakinSkywalkerLightSaber"]
	assert.Check(t, !exists)
}

func TestCallSuccess(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("ObiWanKenobiLightSaber", nil)

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "coruscant"}, "", authCredMock, k8sClient, context.TODO())
	auth, err := apiKey.Call(pipelineMock, context.TODO())

	assert.NilError(t, err)
	assert.Equal(t, string(auth.(v1.Secret).Data["api_key"]), "ObiWanKenobiLightSaber")
}

func TestCallNoApiKeyFail(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("", fmt.Errorf("something went wrong getting the API Key"))

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "coruscant"}, "", authCredMock, k8sClient, context.TODO())

	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "something went wrong getting the API Key")
}

func TestCallInvalidApiKeyFail(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("ASithLightSaber", nil)

	apiKey := NewApiKeyIdentity("jedi", map[string]string{"planet": "coruscant"}, "", authCredMock, k8sClient, context.TODO())
	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "the API Key provided is invalid")
}

func TestGetCredentialsFromClusterSuccess(t *testing.T) {
	apiKey := NewApiKeyIdentity("X-API-KEY", map[string]string{"planet": "coruscant"}, "", nil, k8sClient, nil)

	err := apiKey.GetCredentialsFromCluster(context.TODO())
	assert.NilError(t, err)
	assert.Equal(t, len(apiKey.authorizedCredentials), 2)

	secret1, exists := apiKey.authorizedCredentials["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	assert.Equal(t, apiKeySecret1.String(), secret1.String())

	secret2, exists := apiKey.authorizedCredentials["MasterYodaLightSaber"]
	assert.Check(t, exists)
	assert.Equal(t, apiKeySecret2.String(), secret2.String())
}

type flawedAPIkeyK8sClient struct{}

func (k *flawedAPIkeyK8sClient) Get(_ context.Context, _ client.ObjectKey, _ client.Object) error {
	return nil
}

func (k *flawedAPIkeyK8sClient) List(_ context.Context, list client.ObjectList, _ ...client.ListOption) error {
	return fmt.Errorf("something terribly wrong happened")
}

func TestGetCredentialsFromClusterFail(t *testing.T) {
	apiKey := NewApiKeyIdentity("X-API-KEY", map[string]string{"planet": "coruscant"}, "", nil, &flawedAPIkeyK8sClient{}, context.TODO())

	err := apiKey.GetCredentialsFromCluster(context.TODO())
	assert.Error(t, err, "something terribly wrong happened")
}
