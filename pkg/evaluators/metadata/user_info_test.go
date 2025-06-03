package metadata

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/httptest"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const (
	authServerHost string = "127.0.0.1:9002"
	userInfoClaims string = `{ "sub": "831707be-ef07-4d63-b427-4216309e9897" }`
)

var wellKnownOIDCConfig string = fmt.Sprintf(`{
		"issuer": "http://%s",
		"userinfo_endpoint": "http://%s/userinfo"
	}`, authServerHost, authServerHost)

type userInfoTestData struct {
	ctx            context.Context
	cancel         context.CancelFunc
	newOIDC        auth.OpenIdConfigStore
	userInfo       UserInfo
	authCredMock   *mock_auth.MockAuthCredentials
	pipelineMock   *mock_auth.MockAuthPipeline
	idConfEvalMock *mock_auth.MockIdentityConfigEvaluator
}

func newUserInfoTestData(ctrl *gomock.Controller) userInfoTestData {
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	newOIDC := identity.NewJWTAuthentication(identity.NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%s", authServerHost), 0), authCredMock)
	ctx, cancel := context.WithCancel(context.TODO())
	return userInfoTestData{
		ctx,
		cancel,
		newOIDC,
		UserInfo{newOIDC, ""},
		authCredMock,
		mock_auth.NewMockAuthPipeline(ctrl),
		mock_auth.NewMockIdentityConfigEvaluator(ctrl),
	}
}
func TestMain(m *testing.M) {
	authServer := httptest.NewHttpServerMock(authServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: wellKnownOIDCConfig}
		},
		"/userinfo": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: userInfoClaims}
		},
	})
	defer authServer.Close()
	os.Exit(m.Run())
}

func TestUserInfoCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ta := newUserInfoTestData(ctrl)

	ta.pipelineMock.EXPECT().GetResolvedIdentity().Return(ta.idConfEvalMock, nil)
	ta.idConfEvalMock.EXPECT().GetOpenIdConfig().Return(ta.newOIDC)
	ta.pipelineMock.EXPECT().GetHttp().Return(nil)
	ta.idConfEvalMock.EXPECT().GetAuthCredentials().Return(ta.authCredMock)
	ta.authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("", nil)

	obj, err := ta.userInfo.Call(ta.pipelineMock, ta.ctx)

	assert.NilError(t, err)

	claims := obj.(map[string]interface{})
	assert.Equal(t, "831707be-ef07-4d63-b427-4216309e9897", claims["sub"])
}

func TestUserInfoCanceledContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ta := newUserInfoTestData(ctrl)

	ta.pipelineMock.EXPECT().GetResolvedIdentity().Return(ta.idConfEvalMock, nil)
	ta.idConfEvalMock.EXPECT().GetOpenIdConfig().Return(ta.newOIDC)
	ta.pipelineMock.EXPECT().GetHttp().Return(nil)
	ta.idConfEvalMock.EXPECT().GetAuthCredentials().Return(ta.authCredMock)
	ta.authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("", nil)

	ta.cancel()
	_, err := ta.userInfo.Call(ta.pipelineMock, ta.ctx)

	assert.Error(t, err, "context canceled")
}

func TestUserInfoMissingOIDCConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ta := newUserInfoTestData(ctrl)

	otherOidcEvaluator := identity.NewJWTAuthentication(identity.NewOIDCProviderVerifier(context.TODO(), "http://wrongServer", 0), ta.authCredMock)
	ta.pipelineMock.EXPECT().GetResolvedIdentity().Return(ta.idConfEvalMock, nil)
	ta.idConfEvalMock.EXPECT().GetOpenIdConfig().Return(otherOidcEvaluator)

	_, err := ta.userInfo.Call(ta.pipelineMock, ta.ctx)
	assert.Error(t, err, "missing openid connect configuration")
}
