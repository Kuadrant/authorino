package service

import (
	"context"
	"github.com/3scale-labs/authorino/pkg/config"
	"github.com/3scale-labs/authorino/pkg/config/common"
	"github.com/pkg/errors"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"testing"
)

type configMockOk struct{}
type configMockError struct{}

var (
	callFunctionOk    func(ctx common.AuthContext) (interface{}, error)
	callFunctionError func(ctx common.AuthContext) (interface{}, error)
)

const (
	identityObjectMockOK = `{
				  "acr": "1",
				  "aud": [
					"realm-management",
					"account"
				  ],
				  "email": "luke@skywalker.sw",
				  "email_verified": true,
				  "exp": 1612861412,
				  "family_name": "Skywalker",
				  "given_name": "Luke",
				  "name": "Luke Skywalker",
				  "preferred_username": "luke",
				  "realm_access": {
					"roles": [
					  "jedi-master",
					  "canon",
					  "rebel"
					]
				  },
				  "resource_access": {
					"account": {
					  "roles": [
						"jedi-master",
						"canon"
					  ]
					},
					"realm-management": {
					  "roles": [
						"jedi-master",
						"galactic-alliance",
						"rebel"
					  ]
					}
				  },
				  "scope": "profile email",
				  "session_state": "ca7ad85c-320a-4d1a-bd6f-a8dc680d49e4",
				  "sub": "871e7d12-a7c1-48a6-966b-7a1fcde281af",
				  "typ": "Bearer"
				}`
	metadataObjectMockOK = `[
				  {
					"_id": "44f93c94-a8d0-4b33-8188-8173e86844d2",
					"attributes": {
					  "species": [
						"droid"
					  ],
					  "name": [
						"R2-D2"
					  ],
					  "homeworld": [
						"Naboo"
					  ]
					  "occupation": [
						"Astromech droid"
					  ],
					  "affiliation": [
						"Kingdom of Naboo",
						"Galactic Republic",
						"Rebel Alliance",
						"New Republic",
						"Resistance",
						"C-3PO"
					  ]
					},
					"name": "droid-1",
					"owner": {
					  "id": "871e7d12-a7c1-48a6-966b-7a1fcde281af"
					},
					"ownerManagedAccess": true,
					"resource_scopes": [],
					"uris": [
					  "/droid/1"
					]
				  }
				]`
)

func (m *configMockOk) Call(ctx common.AuthContext) (interface{}, error) {
	return callFunctionOk(ctx)
}
func (m *configMockError) Call(ctx common.AuthContext) (interface{}, error) {
	return callFunctionError(ctx)
}

func TestEvaluateIdentitySuccess(t *testing.T) {
	callFunctionOk = func(ctx common.AuthContext) (interface{}, error) {
		return identityObjectMockOK, nil
	}
	callFunctionError = func(ctx common.AuthContext) (interface{}, error) {
		return nil, errors.New("Failed to evaluate config")
	}

	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &configMockError{}, &configMockOk{})

	apiConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      identityConfigs,
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}

	authContext := NewAuthContext(context.TODO(), nil, apiConfig)

	assert.NilError(t, authContext.EvaluateIdentity())
}

func TestEvaluateIdentityError(t *testing.T) {
	callFunctionError = func(ctx common.AuthContext) (interface{}, error) {
		return nil, errors.New("failed to evaluate config")
	}

	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &configMockError{}, &configMockError{})

	apiConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      identityConfigs,
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}

	authContext := NewAuthContext(context.TODO(), nil, apiConfig)

	assert.Error(t, authContext.EvaluateIdentity(), "error evaluating identity configs")
}

func TestEvaluateMetadataFetchObjects(t *testing.T) {
	callFunctionOk = func(ctx common.AuthContext) (interface{}, error) {
		return metadataObjectMockOK, nil
	}
	callFunctionError = func(ctx common.AuthContext) (interface{}, error) {
		return nil, errors.New("failed to evaluate config")
	}

	var metadataConfigs []common.AuthConfigEvaluator
	metadataConfigs = append(metadataConfigs, &configMockError{}, &configMockOk{})

	apiConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      nil,
		MetadataConfigs:      metadataConfigs,
		AuthorizationConfigs: nil,
	}

	authContext := NewAuthContext(context.TODO(), nil, apiConfig)
	authContext.EvaluateMetadata()
	for _, configObj := range authContext.Metadata {
		assert.Assert(t, is.Contains(configObj, metadataObjectMockOK))
	}
}

func TestEvaluateMetadataFetchNoObjects(t *testing.T) {
	callFunctionError = func(ctx common.AuthContext) (interface{}, error) {
		return nil, errors.New("failed to evaluate config")
	}

	var metadataConfigs []common.AuthConfigEvaluator
	metadataConfigs = append(metadataConfigs, &configMockError{}, &configMockError{})

	apiConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      nil,
		MetadataConfigs:      metadataConfigs,
		AuthorizationConfigs: nil,
	}

	authContext := NewAuthContext(context.TODO(), nil, apiConfig)
	authContext.EvaluateMetadata()
	assert.Assert(t, is.Len(authContext.Metadata, 0))

}

func TestEvaluateAuthorizationOK(t *testing.T) {
	callFunctionOk = func(ctx common.AuthContext) (interface{}, error) {
		return true, nil
	}

	var authorizationConfigs []common.AuthConfigEvaluator
	authorizationConfigs = append(authorizationConfigs, &configMockOk{}, &configMockOk{})

	apiConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      nil,
		MetadataConfigs:      nil,
		AuthorizationConfigs: authorizationConfigs,
	}

	authContext := NewAuthContext(context.TODO(), nil, apiConfig)
	err := authContext.EvaluateAuthorization()
	assert.NilError(t, err)
	for _, configObj := range authContext.Authorization {
		assert.Check(t, configObj)
	}
}

func TestEvaluateAuthorizationError(t *testing.T) {
	callFunctionOk = func(ctx common.AuthContext) (interface{}, error) {
		return true, nil
	}

	callFunctionError = func(ctx common.AuthContext) (interface{}, error) {
		return nil, errors.New("failed to authorize policy")
	}

	var authorizationConfigs []common.AuthConfigEvaluator
	authorizationConfigs = append(authorizationConfigs, &configMockOk{}, &configMockError{})

	apiConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      nil,
		MetadataConfigs:      nil,
		AuthorizationConfigs: authorizationConfigs,
	}

	authContext := NewAuthContext(context.TODO(), nil, apiConfig)
	err := authContext.EvaluateAuthorization()
	assert.Error(t, err, "failed to authorize policy")
}
