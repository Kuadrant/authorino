package auth

import (
	"context"
	"testing"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"gotest.tools/assert"
)

func TestConstants(t *testing.T) {
	assert.Check(t, inCustomHeader == "custom_header")
	assert.Check(t, inAuthHeader == "authorization_header")
	assert.Check(t, inQuery == "query")
	assert.Check(t, credentialNotFoundMsg == "credential not found")
	assert.Check(t, credentialNotFoundInHeaderMsg == "the credential was not found in the request header")
	assert.Check(t, credentialLocationNotSupportedMsg == "the credential location is not supported")
	assert.Check(t, authHeaderNotSetMsg == "the Authorization header is not set")
	assert.Check(t, cookieHeaderNotSetMsg == "the Cookie header is not set")
	assert.Check(t, defaultKeySelector == "Bearer")
}

func TestNewAuthCredential(t *testing.T) {
	creds := NewAuthCredential("api_key", "query")
	assert.Check(t, creds.KeySelector == "api_key")
	assert.Check(t, creds.In == "query")
}

func TestNewAuthCredentialDefaultValues(t *testing.T) {
	creds := NewAuthCredential("", "")
	assert.Check(t, creds.KeySelector == "Bearer")
	assert.Check(t, creds.In == "authorization_header")
}

func TestGetCredentialsLocationNotSupported(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{}

	authCredentials := AuthCredential{
		In: "body",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "the credential location is not supported")
}

func TestGetCredentialsFromCustomHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"x-api-key": "DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		KeySelector: "X-API-KEY",
		In:          "custom_header",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromCustomHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{}

	authCredentials := AuthCredential{
		KeySelector: "X-API-KEY",
		In:          "custom_header",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestGetCredentialsFromAuthHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"authorization": "X-API-KEY DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		KeySelector: "X-API-KEY",
		In:          "authorization_header",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromAuthHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"authorization": "X-API-KEY DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		KeySelector: "Bearer",
		In:          "authorization_header",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestGetCredentialsFromCookieHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "Expires=Tue, 01-Jan-2016 21:47:38 GMT; API-KEY=HumanInstrumentality"},
	}

	authCredentials := AuthCredential{
		KeySelector: "API-KEY",
		In:          "cookie",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "HumanInstrumentality")
}

func TestGetCredentialsFromCookieHeaderFirstKey(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "API-KEY=HumanInstrumentality; Expires=Tue, 01-Jan-2016 21:47:38 GMT"},
	}

	authCredentials := AuthCredential{
		KeySelector: "API-KEY",
		In:          "cookie",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "HumanInstrumentality")
}

func TestGetCredentialsFromCookieHeaderWithEqualSign(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "Expires=Tue, 01-Jan-2016 21:47:38 GMT; API-KEY=SHVtYW5JbnN0cnVtZW50YWxpdHk="},
	}

	authCredentials := AuthCredential{
		KeySelector: "API-KEY",
		In:          "cookie",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "SHVtYW5JbnN0cnVtZW50YWxpdHk=")
}

func TestGetCredentialsFromCookieHeaderNoCookieHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "Expires=Tue, 01-Jan-2016 21:47:38 GMT"},
	}

	authCredentials := AuthCredential{
		KeySelector: "API-KEY",
		In:          "cookie",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")

}

func TestGetCredentialsFromCookieHeaderNoKeyFoundFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{},
	}

	authCredentials := AuthCredential{
		KeySelector: "API-KEY",
		In:          "cookie",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")

}

func TestGetCredentialsFromQuerySuccess(t *testing.T) {
	// as first query param
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?api_key=DasUberApiKey",
	}

	authCredentials := AuthCredential{
		KeySelector: "api_key",
		In:          "query",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")

	// as a nth query param
	httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?third_impact=true&api_key=DasUberApiKey&some=scheisse",
	}

	cred, err = authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromQueryFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?third_impact=true&some=scheisse",
	}

	authCredentials := AuthCredential{
		KeySelector: "api_key",
		In:          "query",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestBuildRequestWithCredentials(t *testing.T) {
	creds := NewAuthCredential("", "")
	req, err := creds.BuildRequestWithCredentials(context.TODO(), "http://example.com", "GET", "123", nil)

	assert.NilError(t, err)
	assert.Equal(t, len(req.Header.Values("Authorization")), 1)
	assert.Equal(t, req.Header.Get("Authorization"), creds.KeySelector+" 123")
}

func TestBuildRequestWithCredentialsEmpty(t *testing.T) {
	creds := NewAuthCredential("", "")
	req, err := creds.BuildRequestWithCredentials(context.TODO(), "http://example.com", "GET", "", nil)

	assert.NilError(t, err)
	assert.Equal(t, len(req.Header.Values("Authorization")), 0)
}
