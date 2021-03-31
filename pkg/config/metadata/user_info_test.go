package metadata

import (
	"context"
	"fmt"
	"os"
	"testing"

	. "github.com/3scale-labs/authorino/pkg/common/mocks"
	"github.com/3scale-labs/authorino/pkg/config/identity"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

const (
	authServerHost string = "127.0.0.1:9002"
	userInfoClaims string = `{ "sub": "831707be-ef07-4d63-b427-4216309e9897" }`
)

var (
	wellKnownOIDCConfig string = fmt.Sprintf(`{
		"issuer": "http://%s",
		"userinfo_endpoint": "http://%s/userinfo"
	}`, authServerHost, authServerHost)
)

// TODO: replace with gomock
type authCredMock struct{}

func (a *authCredMock) GetCredentialsFromReq(*envoy_auth.AttributeContext_HttpRequest) (string, error) {
	return "", nil
}

func TestMain(m *testing.M) {
	authServer := NewHttpServerMock(authServerHost, map[string]HttpServerMockResponses{
		"/.well-known/openid-configuration": {Status: 200, Body: wellKnownOIDCConfig},
		"/userinfo":                         {Status: 200, Body: userInfoClaims},
	})
	defer authServer.Close()
	os.Exit(m.Run())
}

func TestUserInfoCall(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	authContextMock := NewMockAuthContext(ctrl)
	idConfEval := NewMockIdentityConfigEvaluator(ctrl)
	oidcEvaluator, _ := identity.NewOIDC(fmt.Sprintf("http://%s", authServerHost), &authCredMock{})
	idConfEval.EXPECT().GetOIDC().Return(oidcEvaluator)
	authContextMock.EXPECT().GetHttp().Return(nil)
	authContextMock.EXPECT().GetResolvedIdentity().Return(idConfEval, nil)

	userInfo := UserInfo{oidcEvaluator}
	obj, err := userInfo.Call(authContextMock, context.TODO())
	assert.NilError(t, err)

	claims := obj.(map[string]interface{})
	assert.Equal(t, "831707be-ef07-4d63-b427-4216309e9897", claims["sub"])
}

func TestUserInfoCanceledContext(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	authContextMock := NewMockAuthContext(ctrl)
	idConfEval := NewMockIdentityConfigEvaluator(ctrl)
	oidcEvaluator, _ := identity.NewOIDC(fmt.Sprintf("http://%s", authServerHost), &authCredMock{})
	idConfEval.EXPECT().GetOIDC().Return(oidcEvaluator)
	authContextMock.EXPECT().GetHttp().Return(nil)
	authContextMock.EXPECT().GetResolvedIdentity().Return(idConfEval, nil)

	ctx, cancel := context.WithCancel(context.TODO())
	cancel()
	userInfo := UserInfo{oidcEvaluator}
	_, err := userInfo.Call(authContextMock, ctx)
	assert.Error(t, err, "context canceled")
}

func TestUserInfoMissingOIDCConfig(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	authContextMock := NewMockAuthContext(ctrl)
	idConfEval := NewMockIdentityConfigEvaluator(ctrl)
	oidcEvaluator, _ := identity.NewOIDC(fmt.Sprintf("http://%s", authServerHost), &authCredMock{})
	otherOidcEvaluator, _ := identity.NewOIDC("http://wrongServer", &authCredMock{})
	idConfEval.EXPECT().GetOIDC().Return(otherOidcEvaluator)
	authContextMock.EXPECT().GetResolvedIdentity().Return(idConfEval, nil)

	userInfo := UserInfo{oidcEvaluator}
	_, err := userInfo.Call(authContextMock, context.TODO())
	assert.ErrorContains(t, err, "Missing identity for OIDC issuer")
}
