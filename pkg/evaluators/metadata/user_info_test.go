package metadata

import (
	"context"
	"fmt"
	"os"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	. "github.com/golang/mock/gomock"

	"gotest.tools/assert"

	"github.com/kuadrant/authorino/pkg/evaluators/identity"
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
	newOIDC        *identity.OIDC
	userInfo       UserInfo
	authCredMock   *mock_auth.MockAuthCredentials
	pipelineMock   *mock_auth.MockAuthPipeline
	idConfEvalMock *mock_auth.MockIdentityConfigEvaluator
}

func newUserInfoTestData(ctrl *Controller) userInfoTestData {
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	newOIDC := identity.NewOIDC(fmt.Sprintf("http://%s", authServerHost), authCredMock, 0, context.TODO())
	ctx, cancel := context.WithCancel(context.TODO())
	return userInfoTestData{
		ctx,
		cancel,
		newOIDC,
		UserInfo{newOIDC},
		authCredMock,
		mock_auth.NewMockAuthPipeline(ctrl),
		mock_auth.NewMockIdentityConfigEvaluator(ctrl),
	}
}
func TestMain(m *testing.M) {
	authServer := mock_auth.NewHttpServerMock(authServerHost, map[string]mock_auth.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() mock_auth.HttpServerMockResponse {
			return mock_auth.HttpServerMockResponse{Status: 200, Body: wellKnownOIDCConfig}
		},
		"/userinfo": func() mock_auth.HttpServerMockResponse {
			return mock_auth.HttpServerMockResponse{Status: 200, Body: userInfoClaims}
		},
	})
	defer authServer.Close()
	os.Exit(m.Run())
}

func TestUserInfoCall(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	ta := newUserInfoTestData(ctrl)

	ta.authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("", nil)
	ta.idConfEvalMock.EXPECT().GetOIDC().Return(ta.newOIDC)
	ta.pipelineMock.EXPECT().GetHttp().Return(nil)
	ta.pipelineMock.EXPECT().GetResolvedIdentity().Return(ta.idConfEvalMock, nil)

	obj, err := ta.userInfo.Call(ta.pipelineMock, ta.ctx)

	assert.NilError(t, err)

	claims := obj.(map[string]interface{})
	assert.Equal(t, "831707be-ef07-4d63-b427-4216309e9897", claims["sub"])
}

func TestUserInfoCanceledContext(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	ta := newUserInfoTestData(ctrl)

	ta.authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("", nil)
	ta.idConfEvalMock.EXPECT().GetOIDC().Return(ta.newOIDC)
	ta.pipelineMock.EXPECT().GetHttp().Return(nil)
	ta.pipelineMock.EXPECT().GetResolvedIdentity().Return(ta.idConfEvalMock, nil)

	ta.cancel()
	_, err := ta.userInfo.Call(ta.pipelineMock, ta.ctx)

	assert.Error(t, err, "context canceled")
}

func TestUserInfoMissingOIDCConfig(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	ta := newUserInfoTestData(ctrl)

	otherOidcEvaluator := identity.NewOIDC("http://wrongServer", ta.authCredMock, 0, context.TODO())
	ta.idConfEvalMock.EXPECT().GetOIDC().Return(otherOidcEvaluator)
	ta.pipelineMock.EXPECT().GetResolvedIdentity().Return(ta.idConfEvalMock, nil)

	_, err := ta.userInfo.Call(ta.pipelineMock, ta.ctx)
	assert.Error(t, err, "Missing identity for OIDC issuer http://127.0.0.1:9002. Skipping related UserInfo metadata.")
}
