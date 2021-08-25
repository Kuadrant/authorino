package config

import (
	"encoding/json"
	"testing"

	"github.com/kuadrant/authorino/pkg/common"
	mock_common "github.com/kuadrant/authorino/pkg/common/mocks"
	"github.com/kuadrant/authorino/pkg/config/identity"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

func TestIdentityConfig_ResolveExtendedProperties(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	var identityConfig IdentityConfig
	var identityObject interface{}
	var extendedIdentityObject interface{}
	var authData interface{}
	var err error

	// Without extended properties
	identityConfig = IdentityConfig{
		Name:           "test",
		KubernetesAuth: &identity.KubernetesAuth{},
	}

	_ = json.Unmarshal([]byte(`{"sub":"foo","exp":1629884250}`), &identityObject)
	pipelineMock.EXPECT().GetResolvedIdentity().Return(nil, identityObject)

	extendedIdentityObject, err = identityConfig.ResolveExtendedProperties(pipelineMock)
	assert.NilError(t, err)
	assert.DeepEqual(t, identityObject, extendedIdentityObject)

	// With extended properties
	identityConfig = IdentityConfig{
		Name:           "test",
		KubernetesAuth: &identity.KubernetesAuth{},
		ExtendedProperties: []common.JSONProperty{
			{Name: "prop1", Value: common.JSONValue{Static: "value1"}},
			{Name: "prop2", Value: common.JSONValue{Pattern: "auth.identity.sub"}},
		},
	}

	pipelineMock.EXPECT().GetResolvedIdentity().Return(nil, identityObject)

	_ = json.Unmarshal([]byte(`{"context":{},"auth":{"identity":{"sub":"foo","exp":1629884250}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	extendedIdentityObject, err = identityConfig.ResolveExtendedProperties(pipelineMock)
	assert.NilError(t, err)
	extendedIdentityObjectJSON, _ := json.Marshal(extendedIdentityObject)
	assert.Equal(t, string(extendedIdentityObjectJSON), `{"exp":1629884250,"prop1":"value1","prop2":"foo","sub":"foo"}`)
}
