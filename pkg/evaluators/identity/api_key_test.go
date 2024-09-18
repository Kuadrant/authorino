package identity

import (
	"context"
	"fmt"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	k8s "k8s.io/api/core/v1"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_labels "k8s.io/apimachinery/pkg/labels"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

var (
	testAPIKeyK8sSecret1 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "obi-wan", Namespace: "ns1", Labels: map[string]string{"planet": "coruscant"}}, Data: map[string][]byte{"api_key": []byte("ObiWanKenobiLightSaber")}}
	testAPIKeyK8sSecret2 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "yoda", Namespace: "ns2", Labels: map[string]string{"planet": "coruscant"}}, Data: map[string][]byte{"api_key": []byte("MasterYodaLightSaber")}}
	testAPIKeyK8sSecret3 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "anakin", Namespace: "ns2", Labels: map[string]string{"planet": "tatooine"}}, Data: map[string][]byte{"api_key": []byte("AnakinSkywalkerLightSaber")}}
	testAPIKeyK8sClient  = mockK8sClient(testAPIKeyK8sSecret1, testAPIKeyK8sSecret2, testAPIKeyK8sSecret3)
)

func TestConstants(t *testing.T) {
	assert.Equal(t, apiKeySelector, "api_key")
	assert.Equal(t, invalidApiKeyMsg, "the API Key provided is invalid")
}

func TestNewApiKeyIdentityAllNamespaces(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", []string{}, mock_auth.NewMockAuthCredentials(ctrl), testAPIKeyK8sClient, context.TODO())

	assert.Equal(t, apiKey.Name, "jedi")
	assert.Equal(t, apiKey.LabelSelectors.String(), "planet=coruscant")
	assert.Equal(t, apiKey.Namespace, "")
	assert.Equal(t, len(apiKey.KeySelectors), 1)
	assert.Equal(t, apiKey.KeySelectors[0], apiKeySelector)
	assert.Equal(t, len(apiKey.secrets), 2)
	_, exists := apiKey.secrets["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.secrets["MasterYodaLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.secrets["AnakinSkywalkerLightSaber"]
	assert.Check(t, !exists)
}

func TestNewApiKeyIdentitySingleNamespace(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "ns1", []string{}, mock_auth.NewMockAuthCredentials(ctrl), testAPIKeyK8sClient, context.TODO())

	assert.Equal(t, apiKey.Name, "jedi")
	assert.Equal(t, apiKey.LabelSelectors.String(), "planet=coruscant")
	assert.Equal(t, apiKey.Namespace, "ns1")
	assert.Equal(t, len(apiKey.KeySelectors), 1)
	assert.Equal(t, apiKey.KeySelectors[0], apiKeySelector)
	assert.Equal(t, len(apiKey.secrets), 1)
	_, exists := apiKey.secrets["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.secrets["MasterYodaLightSaber"]
	assert.Check(t, !exists)
	_, exists = apiKey.secrets["AnakinSkywalkerLightSaber"]
	assert.Check(t, !exists)
}

func TestNewApiKeyIdentityMultipleKeySelectors(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "ns1", []string{"no_op"}, mock_auth.NewMockAuthCredentials(ctrl), testAPIKeyK8sClient, context.TODO())

	assert.Equal(t, apiKey.Name, "jedi")
	assert.Equal(t, apiKey.LabelSelectors.String(), "planet=coruscant")
	assert.Equal(t, apiKey.Namespace, "ns1")
	assert.Equal(t, len(apiKey.KeySelectors), 2)
	assert.Equal(t, apiKey.KeySelectors[0], "no_op")
	assert.Equal(t, apiKey.KeySelectors[1], apiKeySelector)
	assert.Equal(t, len(apiKey.secrets), 1)
	_, exists := apiKey.secrets["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	_, exists = apiKey.secrets["MasterYodaLightSaber"]
	assert.Check(t, !exists)
	_, exists = apiKey.secrets["AnakinSkywalkerLightSaber"]
	assert.Check(t, !exists)
}

func TestCallSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("ObiWanKenobiLightSaber", nil)

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", []string{}, authCredMock, testAPIKeyK8sClient, context.TODO())
	auth, err := apiKey.Call(pipelineMock, context.TODO())

	assert.NilError(t, err)
	assert.Equal(t, string(auth.(k8s.Secret).Data["api_key"]), "ObiWanKenobiLightSaber")
}

func TestCallNoApiKeyFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("", fmt.Errorf("something went wrong getting the API Key"))

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", []string{}, authCredMock, testAPIKeyK8sClient, context.TODO())

	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "something went wrong getting the API Key")
}

func TestCallInvalidApiKeyFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("ASithLightSaber", nil)

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", []string{}, authCredMock, testAPIKeyK8sClient, context.TODO())
	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "the API Key provided is invalid")
}

func TestLoadSecretsSuccess(t *testing.T) {
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("X-API-KEY", selector, "", []string{}, nil, testAPIKeyK8sClient, nil)

	err := apiKey.loadSecrets(context.TODO())
	assert.NilError(t, err)
	assert.Equal(t, len(apiKey.secrets), 2)

	secret1, exists := apiKey.secrets["ObiWanKenobiLightSaber"]
	assert.Check(t, exists)
	assert.Equal(t, testAPIKeyK8sSecret1.String(), secret1.String())

	secret2, exists := apiKey.secrets["MasterYodaLightSaber"]
	assert.Check(t, exists)
	assert.Equal(t, testAPIKeyK8sSecret2.String(), secret2.String())
}

func TestLoadSecretsFail(t *testing.T) {
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("X-API-KEY", selector, "", []string{}, nil, &flawedAPIkeyK8sClient{}, context.TODO())

	err := apiKey.loadSecrets(context.TODO())
	assert.Error(t, err, "something terribly wrong happened")
}

func BenchmarkAPIKeyAuthn(b *testing.B) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetHttp().Return(nil).MinTimes(1)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("ObiWanKenobiLightSaber", nil).MinTimes(1)
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", []string{}, authCredMock, testAPIKeyK8sClient, context.TODO())

	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = apiKey.Call(pipelineMock, context.TODO())
	}
	b.StopTimer()
	assert.NilError(b, err)
}
