package metadata

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	mock_common "github.com/3scale-labs/authorino/pkg/common/mocks"

	. "github.com/golang/mock/gomock"

	"gotest.tools/assert"

	"github.com/3scale-labs/authorino/pkg/config/identity"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const (
	authServerHost string = "127.0.0.1:9001"
	userInfoClaims string = `{ "sub": "831707be-ef07-4d63-b427-4216309e9897" }`
)

var (
	wellKnownOIDCConfig string = fmt.Sprintf(`{
		"issuer": "http://%s",
		"userinfo_endpoint": "http://%s/userinfo"
	}`, authServerHost, authServerHost)

	userInfo UserInfo
	newOIDC  *identity.OIDC
	ctx      context.Context
	cancel   context.CancelFunc
)

// TODO: replace with gomock
type authCredMock struct{}

func (a *authCredMock) GetCredentialsFromReq(*envoy_auth.AttributeContext_HttpRequest) (string, error) {
	return "", nil
}

func TestMain(m *testing.M) {
	authServer := mockHTTPServer()
	defer authServer.Close()
	setup()
	os.Exit(m.Run())
}

func setup() {
	newOIDC, _ = identity.NewOIDC(fmt.Sprintf("http://%s", authServerHost), &authCredMock{})
	userInfo = UserInfo{newOIDC}
	ctx, cancel = context.WithCancel(context.TODO())
}

func mockHTTPServer() *httptest.Server {
	responses := make(map[string]string)
	responses["/.well-known/openid-configuration"] = wellKnownOIDCConfig
	responses["/userinfo"] = userInfoClaims

	listener, err := net.Listen("tcp", authServerHost)
	if err != nil {
		panic(err)
	}
	handler := func(rw http.ResponseWriter, req *http.Request) {
		for url, response := range responses {
			if url == req.URL.String() {
				_, _ = rw.Write([]byte(response))
				break
			}
		}
	}
	authServer := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(handler)}}
	authServer.Start()
	return authServer
}

func TestCall(t *testing.T) {

	ctrl := NewController(t)
	defer ctrl.Finish()

	authContextMock := mock_common.NewMockAuthContext(ctrl)
	idConfEval := mock_common.NewMockIdentityConfigEvaluator(ctrl)
	idConfEval.EXPECT().GetOIDC().Return(newOIDC)
	authContextMock.EXPECT().GetHttp().Return(nil)
	authContextMock.EXPECT().GetResolvedIdentity().Return(idConfEval, nil)

	obj, err := userInfo.Call(authContextMock, ctx)
	assert.NilError(t, err)

	claims := obj.(map[string]interface{})
	assert.Equal(t, "831707be-ef07-4d63-b427-4216309e9897", claims["sub"])
}

func TestCanceledContext(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	authContextMock := mock_common.NewMockAuthContext(ctrl)
	idConfEval := mock_common.NewMockIdentityConfigEvaluator(ctrl)
	idConfEval.EXPECT().GetOIDC().Return(newOIDC)
	authContextMock.EXPECT().GetHttp().Return(nil)
	authContextMock.EXPECT().GetResolvedIdentity().Return(idConfEval, nil)

	cancel()
	_, err := userInfo.Call(authContextMock, ctx)
	assert.Error(t, err, "context canceled")
}

func TestMissingOIDCConfig(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	authContextMock := mock_common.NewMockAuthContext(ctrl)
	idConfEval := mock_common.NewMockIdentityConfigEvaluator(ctrl)
	wrongOidc, _ := identity.NewOIDC(fmt.Sprintf("http://wrongServer"), &authCredMock{})
	idConfEval.EXPECT().GetOIDC().Return(wrongOidc)
	authContextMock.EXPECT().GetResolvedIdentity().Return(idConfEval, nil)

	_, err := userInfo.Call(authContextMock, ctx)
	assert.Error(t, err, "Missing identity for OIDC issuer http://127.0.0.1:9001. Skipping related UserInfo metadata.")
}
