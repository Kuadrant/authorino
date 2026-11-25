package evaluators

import (
	"context"
	gojson "encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/json"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestIdentityConfig_ResolveExtendedProperties(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	var identityConfig IdentityConfig
	var identityObject interface{}
	var extendedIdentityObject interface{}
	var err error

	// Without extended properties
	identityConfig = IdentityConfig{
		Name:           "test",
		KubernetesAuth: &identity.KubernetesAuth{},
	}

	_ = gojson.Unmarshal([]byte(`{"sub":"foo","exp":1629884250}`), &identityObject)
	pipelineMock.EXPECT().GetResolvedIdentity().Return(nil, identityObject)

	extendedIdentityObject, err = identityConfig.ResolveExtendedProperties(pipelineMock)
	assert.NilError(t, err)
	assert.DeepEqual(t, identityObject, extendedIdentityObject)

	// With extended properties
	identityConfig = IdentityConfig{
		Name:           "test",
		KubernetesAuth: &identity.KubernetesAuth{},
		ExtendedProperties: []IdentityExtension{
			NewIdentityExtension("prop1", &json.JSONValue{Static: "value1"}, true),
			NewIdentityExtension("prop2", &json.JSONValue{Pattern: "auth.identity.sub"}, true),
		},
	}

	pipelineMock.EXPECT().GetResolvedIdentity().Return(nil, identityObject)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{},"auth":{"identity":{"sub":"foo","exp":1629884250}}}`)

	extendedIdentityObject, err = identityConfig.ResolveExtendedProperties(pipelineMock)
	assert.NilError(t, err)
	extendedIdentityObjectJSON, _ := gojson.Marshal(extendedIdentityObject)
	assert.Equal(t, string(extendedIdentityObjectJSON), `{"exp":1629884250,"prop1":"value1","prop2":"foo","sub":"foo"}`)
}

func TestIdentityConfigLoadsK8sSecretBasedIdentities(t *testing.T) {
	lists := 0
	k8sClient := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lists++
			return c.List(ctx, list, opts...)
		},
	}).Build()

	testCases := map[string]*IdentityConfig{
		"api key": {Name: "api-key", APIKey: identity.NewApiKeyIdentity("api-key", labels.Everything(), "", nil, k8sClient, t.Context())},
		"mtls":    {Name: "mtls", MTLS: identity.NewMTLSIdentity("mtls", labels.Everything(), "", "", "", nil, k8sClient, t.Context())},
	}
	for name, config := range testCases {
		t.Run(name, func(t *testing.T) {
			before := lists
			assert.NilError(t, config.LoadK8sSecretBasedIdentities(t.Context()))
			assert.Equal(t, lists, before+1)
		})
	}

	// other identities have no Secrets to list
	before := lists
	assert.NilError(t, (&IdentityConfig{Name: "k8s", KubernetesAuth: &identity.KubernetesAuth{}}).LoadK8sSecretBasedIdentities(t.Context()))
	assert.Equal(t, lists, before)
}
