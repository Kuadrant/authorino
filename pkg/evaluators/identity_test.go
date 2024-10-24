package evaluators

import (
	gojson "encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/json"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
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
			NewIdentityExtension("prop1", json.JSONValue{Static: "value1"}, true),
			NewIdentityExtension("prop2", json.JSONValue{Pattern: "auth.identity.sub"}, true),
		},
	}

	pipelineMock.EXPECT().GetResolvedIdentity().Return(nil, identityObject)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{},"auth":{"identity":{"sub":"foo","exp":1629884250}}}`)

	extendedIdentityObject, err = identityConfig.ResolveExtendedProperties(pipelineMock)
	assert.NilError(t, err)
	extendedIdentityObjectJSON, _ := gojson.Marshal(extendedIdentityObject)
	assert.Equal(t, string(extendedIdentityObjectJSON), `{"exp":1629884250,"prop1":"value1","prop2":"foo","sub":"foo"}`)
}
