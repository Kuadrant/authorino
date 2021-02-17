package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"gopkg.in/yaml.v2"
	"gotest.tools/assert"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"
	"github.com/3scale-labs/authorino/pkg/config/identity"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const (
	authServerHost string = "127.0.0.1:9001"
	userInfoClaims string = `{ "sub": "831707be-ef07-4d63-b427-4216309e9897" }`
	rawRequest     string = `{
		"attributes": {
			"request": {
				"http": {
					"headers": {
						"authorization": "Bearer n3ex87bye9238ry8"
					}
				}
			}
		}
	}`
)

var (
	rawAPIConfig string = fmt.Sprintf(`
identity:
  - name: auth-server
    oidc:
      endpoint: http://%s
    credentials:
      in: authorization_header
      key_selector: Bearer
metadata:
  - name: userinfo-auth-server
    userinfo:
      oidc: auth-server
`, authServerHost)

	wellKnownOIDCConfig string = fmt.Sprintf(`{
		"issuer": "http://%s",
		"userinfo_endpoint": "http://%s/userinfo"
	}`, authServerHost, authServerHost)

	authContext *__AuthContext
	userInfo    UserInfo
	ctx         context.Context
	cancel      context.CancelFunc
)

type __Identity struct {
	Name        string                          `yaml:"name"`
	Credentials auth_credentials.AuthCredential `yaml:"credentials"`
	OIDC        *identity.OIDC                  `yaml:"oidc"`
}

func (i *__Identity) Call(a common.AuthContext, c context.Context) (interface{}, error) {
	return nil, nil
}

func (i *__Identity) GetOIDC() interface{} {
	return &identity.OIDC{
		Endpoint:    i.OIDC.Endpoint,
		Credentials: &i.Credentials,
	}
}

type __Metadata struct {
	Name     string    `yaml:"name"`
	UserInfo *UserInfo `yaml:"userinfo"`
}

type __AuthContext struct {
	Identity []__Identity `yaml:"identity"`
	Metadata []__Metadata `yaml:"metadata"`
}

func (a *__AuthContext) GetParentContext() *context.Context {
	ctx := context.TODO()
	return &ctx
}

func (a *__AuthContext) GetRequest() *envoy_auth.CheckRequest {
	req := envoy_auth.CheckRequest{}
	_ = json.Unmarshal([]byte(rawRequest), &req)
	return &req
}

func (a *__AuthContext) GetHttp() *envoy_auth.AttributeContext_HttpRequest {
	return a.GetRequest().GetAttributes().GetRequest().GetHttp()
}

func (a *__AuthContext) GetAPI() interface{} {
	return nil
}

func (a *__AuthContext) GetIdentity() interface{} {
	return a.Identity[0]
}

func (a *__AuthContext) GetMetadata() map[string]interface{} {
	m := make(map[string]interface{})
	m[a.Metadata[0].Name] = a.Metadata[0].UserInfo
	return m
}

func (a *__AuthContext) FindIdentityConfigByName(name string) (interface{}, error) {
	id := a.Identity[0]
	if id.Name == name {
		return &id, nil
	} else {
		return nil, fmt.Errorf("cannot find config")
	}
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}

func setup() {
	if err := yaml.Unmarshal([]byte(rawAPIConfig), &authContext); err != nil {
		panic(err)
	}
	userInfo = *authContext.Metadata[0].UserInfo
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
				rw.Write([]byte(response))
				break
			}
		}
	}
	authServer := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(handler)}}
	authServer.Start()
	return authServer
}

func TestCall(t *testing.T) {
	authServer := mockHTTPServer()
	defer authServer.Close()

	obj, err := userInfo.Call(authContext, ctx)
	assert.NilError(t, err)

	claims := obj.(map[string]interface{})
	assert.Equal(t, "831707be-ef07-4d63-b427-4216309e9897", claims["sub"])
}

func TestCanceledContext(t *testing.T) {
	cancel()
	_, err := userInfo.Call(authContext, ctx)
	assert.Error(t, err, "context canceled")
}

func TestMissingOIDCConfig(t *testing.T) {
	authContext.Identity[0].Name = "other" // tricking the auth context not to find the right config
	_, err := userInfo.Call(authContext, ctx)
	assert.Error(t, err, "Null OIDC object for config auth-server. Skipping related UserInfo metadata.")
}
