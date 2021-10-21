package response

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kuadrant/authorino/pkg/common"
	mock_common "github.com/kuadrant/authorino/pkg/common/mocks"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/mock/gomock"
	jose "gopkg.in/square/go-jose.v2"
	"gotest.tools/assert"
)

const (
	ellipticCurveSigningKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDHvuf81gVlWGo0hmXGTAnA/HVxGuH8vOc7/8jewcVvqoAoGCCqGSM49
AwEHoUQDQgAETJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZxJKDysoGwn
cnUvHIu23SgW+Ee9lxSmZGhO4eTdQeKxMA==
-----END EC PRIVATE KEY-----`

	rsaSigningKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

	someX509Cert = `-----BEGIN CERTIFICATE-----
MIIGwjCCBKqgAwIBAgIUJzDCEo9B7q3q+q5lJFvITLyBiAAwDQYJKoZIhvcNAQEL
BQAwgaIxCzAJBgNVBAYTAkVTMRIwEAYDVQQIDAlCYXJjZWxvbmExEjAQBgNVBAcM
CUJhcmNlbG9uYTEWMBQGA1UECgwNUmVkIEhhdCwgSW5jLjEXMBUGA1UECwwOUmVk
IEhhdCAzc2NhbGUxOjA4BgNVBAMMMUtleWNsb2FrIFNlcnZlciBvbiAzc2NhbGUg
T3BlblNoaWZ0IGRldmVsIGNsdXN0ZXIwHhcNMjAwNTEzMTM1NTEyWhcNMzAwNTEx
MTM1NTEyWjCBojELMAkGA1UEBhMCRVMxEjAQBgNVBAgMCUJhcmNlbG9uYTESMBAG
A1UEBwwJQmFyY2Vsb25hMRYwFAYDVQQKDA1SZWQgSGF0LCBJbmMuMRcwFQYDVQQL
DA5SZWQgSGF0IDNzY2FsZTE6MDgGA1UEAwwxS2V5Y2xvYWsgU2VydmVyIG9uIDNz
Y2FsZSBPcGVuU2hpZnQgZGV2ZWwgY2x1c3RlcjCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBALEP5Ef+JTO07E6bsjquMOTRWyXjfN6nau6VGpRpVHOmilkJ
cw39NsxWNCbI619OA+uYCB9TOvAikwEljsYDe5nVYDinNdogln5S+bsc0yIFS320
x/GpMBRWMSJFo1uBQNs9aAl30QGl+GTpKHlME/z0caXRRRPd45926Sf09tMfq5Gf
LSFqLt+hpOpPByZ9db8yg31rLlULHPrJ0QC2/1G/A4o7BjC+lLxP8kWL+R0PzF2n
pSFdhV11yFWHC+X7gxo7RDbiz2hfWeEXPUWQHuZ2+iDzasJgMficslPdaffUNArC
9cIbJTQqEKJ3Ob43Nu7ufvANcXrioBsVGLPxK90s+3sZAI0Iyf0BHu7XQoy/5Sl6
nN5/AxiZyQjAQWXN9TLHGqO0/NLpydO/tQkV/fkLUJDlas7/5wGpO+g62nA+frV0
AnC7Yvcx5CYBnTlpU194XtiXdrWvJ/PKvbXq3tk8IciKAV29PIi8Miv8+UF/p3PQ
oCdipAeSsBxtdiVbHy6ibllSwNN0QbzezncPxEE+5FwGDljW69PN+LkpQV3OfNIP
OW++HI0VK8WtLbfVUEIiiGQDhngp/HpI8DThh5ZUVPgYjZo8zDGC8vGHvjfioPyL
t6grzq+mNHxSSOJa4apte/Bz8Jqmjuegy1fbAlYpG6kxrIzq4XRiqVdTMetbAgMB
AAGjge0wgeowHQYDVR0OBBYEFCa8PvO0lTNo1ohbif/ubPBkKIdnMB8GA1UdIwQY
MBaAFCa8PvO0lTNo1ohbif/ubPBkKIdnMA8GA1UdEwEB/wQFMAMBAf8wgZYGA1Ud
EQSBjjCBi4I7a2V5Y2xvYWsta2V5Y2xvYWstb3BlcmF0b3IuYXBwcy5kZXYtZW5n
LW9jcDQtMy5kZXYuM3NjYS5uZXSCHmtleWNsb2FrLmtleWNsb2FrLW9wZXJhdG9y
LnN2Y4Isa2V5Y2xvYWsua2V5Y2xvYWstb3BlcmF0b3Iuc3ZjLmNsdXN0ZXIubG9j
YWwwDQYJKoZIhvcNAQELBQADggIBAIFfr2hTkMoVAJ7UmbfsIVRY+0Uj2kkkKwme
VJ8gbMAbH51JhDCjnj7cIlKDszWZh1L7D9jXjqfVip6w8j1pekaM62IlupUjfdE9
c1Ngv8Za45cXM62UDCKUfrOI2vbIBqyCoPrgwzeRoeAcdFuIiP7VcZJ/qrLIB79T
LXEkU54UHOHOcAX2IDWI1dWFAdYtMlEGlTKfd/uVOGOu/hM5kRn41xAeAEfYFv2G
xSZU94oBZ2erRYQ2IzRNG0tyrnHw9LZSWSj5G/Ifq6MY0zYnMLD/TWSc9u5zoLMp
NemAX981WKXUsedPfJI1V2RVpwyy1qM21nF3k2SXN7QODd0l+Mdb29hse/jVsAG3
gdrxLpStOq5A14nrhijnvHjfAg5uivd0iRRqTkZuHwQ/rwW9Zbpk+JiLHsY+sHVJ
f80uPz81y7GMAJzODS8HZAwx9+ktubT30p9gawd1xWdejAplZeRt6CJFEQyP5KDj
2PNGOJJ1Kiil7twEI6219IKyxdt4XRi9qAbHmdlvYIZc5vpF5QVzwO80s+XNnfAJ
91qCNCk1QgribxXUhn2ueX9Dzz2yt6Oxr2/qqVDuStGjQdlmESVYJMCVKEHb26y/
ENL8WHfRD6zDCGUN0EcaqYb7NriVNRBasxU9yfcsAQi1wjSje4OhEgGc5o8Ur7ID
JIyrQfr9
-----END CERTIFICATE-----`
)

func TestNewSigningKey(t *testing.T) {
	var key *jose.JSONWebKey
	var err error

	key, err = NewSigningKey("my-signing-key", "ES256", []byte(`-----BEGIN EC PRIVATE KEY-----
invalid
-----END EC PRIVATE KEY-----`))
	assert.Check(t, key == nil)
	assert.Error(t, err, "failed to decode PEM file")

	key, err = NewSigningKey("my-signing-key", "ES256", []byte(someX509Cert))
	assert.Check(t, key == nil)
	assert.Error(t, err, "invalid signing key algorithm")

	key, err = NewSigningKey("my-signing-key", "ES256", []byte(ellipticCurveSigningKey))
	assert.NilError(t, err)
	assert.Equal(t, key.KeyID, "my-signing-key")
	assert.Equal(t, key.Algorithm, "ES256")
	assert.Equal(t, key.Use, "sig")
	assert.Check(t, key.Valid())

	key, err = NewSigningKey("my-signing-key", "RS256", []byte(rsaSigningKey))
	assert.NilError(t, err)
	assert.Equal(t, key.KeyID, "my-signing-key")
	assert.Equal(t, key.Algorithm, "RS256")
	assert.Equal(t, key.Use, "sig")
	assert.Check(t, key.Valid())
}

func TestNewWristbandConfig(t *testing.T) {
	signingKeys := []jose.JSONWebKey{}

	var wristbandIssuer *Wristband
	var err error

	tokenDuration := int64(500)
	wristbandIssuer, err = NewWristbandConfig("http://authorino", []common.JSONProperty{}, &tokenDuration, signingKeys)
	assert.Check(t, wristbandIssuer == nil)
	assert.Error(t, err, "missing at least one signing key")

	signingKey, _ := NewSigningKey("my-signing-key", "ES256", []byte(ellipticCurveSigningKey))
	signingKeys = append(signingKeys, *signingKey)

	wristbandIssuer, err = NewWristbandConfig("http://authorino", []common.JSONProperty{}, nil, signingKeys)
	assert.NilError(t, err)
	assert.Equal(t, wristbandIssuer.TokenDuration, DEFAULT_WRISTBAND_DURATION)
}

func TestWristbandCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	claims := []common.JSONProperty{
		{
			Name:  "sta",
			Value: common.JSONValue{Static: "foo"},
		},
		{
			Name:  "dyn",
			Value: common.JSONValue{Pattern: "auth.identity"},
		},
	}
	signingKey, _ := NewSigningKey("my-signing-key", "ES256", []byte(ellipticCurveSigningKey))
	signingKeys := []jose.JSONWebKey{*signingKey}
	wristbandIssuer, _ := NewWristbandConfig("http://authorino", claims, nil, signingKeys)

	type authorizationData struct {
		Context  *envoy_auth.AttributeContext `json:"context"`
		AuthData map[string]interface{}       `json:"auth"`
	}
	postAuthzData := &authorizationData{
		Context: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-secret-header": "no-one-knows",
						"x-origin":        "some-origin",
					},
				},
			},
		},
		AuthData: map[string]interface{}{
			"identity": "some-user-data",
		},
	}

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)
	identityConfigMock := mock_common.NewMockIdentityConfigEvaluator(ctrl)
	identityConfigMock.EXPECT().GetOIDC()
	pipelineMock.EXPECT().GetResolvedIdentity().Return(identityConfigMock, nil)
	pipelineMock.EXPECT().GetPostAuthorizationData().Return(postAuthzData)
	encodedWristband, err := wristbandIssuer.Call(pipelineMock, context.TODO())
	assert.NilError(t, err)

	type wristbandData struct {
		Issuer             string `json:"iss"`
		Subject            string `json:"sub"`
		StaticCustomClaim  string `json:"sta"`
		DynamicCustomClaim string `json:"dyn"`
	}

	jwt, _ := parseJWT(fmt.Sprintf("%v", encodedWristband))
	var wristband wristbandData
	_ = json.Unmarshal(jwt, &wristband)

	assert.Equal(t, wristband.Issuer, "http://authorino")
	assert.Equal(t, wristband.Subject, "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b")
	assert.Equal(t, wristband.StaticCustomClaim, "foo")
	assert.Equal(t, wristband.DynamicCustomClaim, "some-user-data")
}

func TestGetIssuer(t *testing.T) {}

func TestOpenIDConfig(t *testing.T) {}

func TestJWKS(t *testing.T) {}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}
