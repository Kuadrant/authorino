package identity

import (
	"context"
	"fmt"
	"sync"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	k8s "k8s.io/api/core/v1"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_labels "k8s.io/apimachinery/pkg/labels"

	gomock "go.uber.org/mock/gomock"
	"gotest.tools/assert"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
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
	apiKey := NewApiKeyIdentity("jedi", selector, "", mock_auth.NewMockAuthCredentials(ctrl), testAPIKeyK8sClient, context.TODO())

	assert.Equal(t, apiKey.Name, "jedi")
	assert.Equal(t, apiKey.LabelSelectors.String(), "planet=coruscant")
	assert.Equal(t, apiKey.Namespace, "")
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
	apiKey := NewApiKeyIdentity("jedi", selector, "ns1", mock_auth.NewMockAuthCredentials(ctrl), testAPIKeyK8sClient, context.TODO())

	assert.Equal(t, apiKey.Name, "jedi")
	assert.Equal(t, apiKey.LabelSelectors.String(), "planet=coruscant")
	assert.Equal(t, apiKey.Namespace, "ns1")
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
	authCredMock.EXPECT().GetCredentialsFromAuthReq(gomock.Any()).Return("ObiWanKenobiLightSaber", nil)

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", authCredMock, testAPIKeyK8sClient, context.TODO())
	auth, err := apiKey.Call(pipelineMock, context.TODO())

	assert.NilError(t, err)
	assert.Equal(t, string(auth.(k8s.Secret).Data["api_key"]), "ObiWanKenobiLightSaber")
}

func TestCallNoApiKeyFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(gomock.Any()).Return("", fmt.Errorf("something went wrong getting the API Key"))

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", authCredMock, testAPIKeyK8sClient, context.TODO())

	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "something went wrong getting the API Key")
}

func TestCallInvalidApiKeyFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pipelineMock := mockAuthPipeline(ctrl)

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(gomock.Any()).Return("ASithLightSaber", nil)

	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", authCredMock, testAPIKeyK8sClient, context.TODO())
	_, err := apiKey.Call(pipelineMock, context.TODO())

	assert.Error(t, err, "the API Key provided is invalid")
}

func TestLoadSecretsSuccess(t *testing.T) {
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("X-API-KEY", selector, "", nil, testAPIKeyK8sClient, nil)

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
	apiKey := NewApiKeyIdentity("X-API-KEY", selector, "", nil, &flawedAPIkeyK8sClient{}, context.TODO())

	err := apiKey.loadSecrets(context.TODO())
	assert.Error(t, err, "something terribly wrong happened")
}

func BenchmarkAPIKeyAuthn(b *testing.B) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetHttp().Return(nil).MinTimes(1)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(gomock.Any()).Return("ObiWanKenobiLightSaber", nil).MinTimes(1)
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", authCredMock, testAPIKeyK8sClient, context.TODO())

	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = apiKey.Call(pipelineMock, context.TODO())
	}
	b.StopTimer()
	assert.NilError(b, err)
}

func TestLoadK8sSecretBasedIdentitiesReplacesAPIKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := mockK8sClient(testAPIKeyK8sSecret1.DeepCopy())
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", mock_auth.NewMockAuthCredentials(ctrl), client, t.Context())

	// one Secret deleted and one created since the identity was built
	assert.NilError(t, client.Delete(t.Context(), testAPIKeyK8sSecret1.DeepCopy()))
	created := testAPIKeyK8sSecret2.DeepCopy()
	created.ResourceVersion = ""
	assert.NilError(t, client.Create(t.Context(), created))

	assert.NilError(t, apiKey.LoadK8sSecretBasedIdentities(t.Context()))
	_, exists := apiKey.secrets["ObiWanKenobiLightSaber"]
	assert.Check(t, !exists, "expected the API key of the deleted Secret to be dropped")
	_, exists = apiKey.secrets["MasterYodaLightSaber"]
	assert.Check(t, exists, "expected the API key of the created Secret to be loaded")
}

func TestLoadK8sSecretBasedIdentitiesKeepsAPIKeysWhenTheListFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "ns1", mock_auth.NewMockAuthCredentials(ctrl), testAPIKeyK8sClient, t.Context())
	apiKey.k8sClient = &flawedAPIkeyK8sClient{}

	assert.Check(t, apiKey.LoadK8sSecretBasedIdentities(t.Context()) != nil)
	_, exists := apiKey.secrets["ObiWanKenobiLightSaber"]
	assert.Check(t, exists, "expected the API keys to be kept")
}

// lockCheckingReader fails the test when the Secrets are listed without the identity's write lock.
// A list read before an add or revoke that is applied first would undo it when the list replaces
// the identities.
type lockCheckingReader struct {
	k8s_client.Reader
	t     *testing.T
	mutex *sync.RWMutex
}

func (r lockCheckingReader) List(ctx context.Context, list k8s_client.ObjectList, opts ...k8s_client.ListOption) error {
	if r.mutex.TryRLock() {
		r.mutex.RUnlock()
		r.t.Error("listed the Secrets without holding the write lock")
	}
	return r.Reader.List(ctx, list, opts...)
}

func TestLoadK8sSecretBasedIdentitiesListsAPIKeysUnderTheWriteLock(t *testing.T) {
	ctrl := gomock.NewController(t)
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", mock_auth.NewMockAuthCredentials(ctrl), testAPIKeyK8sClient, t.Context())
	apiKey.k8sClient = lockCheckingReader{Reader: testAPIKeyK8sClient, t: t, mutex: &apiKey.mutex}

	assert.NilError(t, apiKey.LoadK8sSecretBasedIdentities(t.Context()))
}

func TestAPIKeyAddK8sSecretBasedIdentityUpdatesMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(gomock.Any()).Return("ObiWanKenobiLightSaber", nil)
	selector, _ := k8s_labels.Parse("planet=coruscant")
	apiKey := NewApiKeyIdentity("jedi", selector, "", authCredMock, mockK8sClient(testAPIKeyK8sSecret1.DeepCopy()), t.Context())

	// same key, new labels: the identity is the Secret, so authorization rules read them
	updated := testAPIKeyK8sSecret1.DeepCopy()
	updated.Labels = map[string]string{"planet": "coruscant", "rank": "master"}
	apiKey.AddK8sSecretBasedIdentity(t.Context(), *updated)

	identity, err := apiKey.Call(mockAuthPipeline(ctrl), t.Context())
	assert.NilError(t, err)
	assert.DeepEqual(t, identity.(k8s.Secret).Labels, updated.Labels)
}
