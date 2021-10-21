package metadata

import (
	"context"
	"fmt"
	"os"
	"testing"

	. "github.com/kuadrant/authorino/pkg/common/auth_credentials/mocks"
	. "github.com/kuadrant/authorino/pkg/common/mocks"

	. "github.com/golang/mock/gomock"

	"gotest.tools/assert"

	"github.com/kuadrant/authorino/pkg/config/identity"
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
	authCredMock   *MockAuthCredentials
	pipelineMock   *MockAuthPipeline
	idConfEvalMock *MockIdentityConfigEvaluator
}

func newUserInfoTestData(ctrl *Controller) userInfoTestData {
	authCredMock := NewMockAuthCredentials(ctrl)
	newOIDC := identity.NewOIDC(fmt.Sprintf("http://%s", authServerHost), authCredMock, context.TODO())
	ctx, cancel := context.WithCancel(context.TODO())
	return userInfoTestData{
		ctx,
		cancel,
		newOIDC,
		UserInfo{newOIDC},
		authCredMock,
		NewMockAuthPipeline(ctrl),
		NewMockIdentityConfigEvaluator(ctrl),
	}
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

	otherOidcEvaluator := identity.NewOIDC("http://wrongServer", ta.authCredMock, context.TODO())
	ta.idConfEvalMock.EXPECT().GetOIDC().Return(otherOidcEvaluator)
	ta.pipelineMock.EXPECT().GetResolvedIdentity().Return(ta.idConfEvalMock, nil)

	_, err := ta.userInfo.Call(ta.pipelineMock, ta.ctx)
	assert.Error(t, err, "Missing identity for OIDC issuer http://127.0.0.1:9002. Skipping related UserInfo metadata.")
}
