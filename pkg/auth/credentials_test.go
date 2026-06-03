package auth

import (
	"testing"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	httputil "github.com/kuadrant/authorino/pkg/http"
	"gotest.tools/assert"
)

func TestConstants(t *testing.T) {
	assert.Check(t, credentialNotFoundMsg == "credential not found")
	assert.Check(t, credentialNotFoundInHeaderMsg == "the credential was not found in the request header")
	assert.Check(t, credentialLocationNotSupportedMsg == "the credential location is not supported")
	assert.Check(t, authHeaderNotSetMsg == "the Authorization header is not set")
	assert.Check(t, cookieHeaderNotSetMsg == "the Cookie header is not set")
	assert.Check(t, defaultCredentialLocationIdentifier == "Bearer")
}

func TestNewAuthCredential(t *testing.T) {
	creds := NewAuthCredential(httputil.InQuery, "api_key")
	assert.Check(t, creds.Identifier == "api_key")
	assert.Check(t, creds.Placement == httputil.InQuery)
}

func TestNewAuthCredentialDefaultValues(t *testing.T) {
	creds := NewAuthCredential("", "")
	assert.Check(t, creds.Identifier == "Bearer")
	assert.Check(t, creds.Placement == httputil.InAuthorizationHeader)
}

func TestGetCredentialsLocationNotSupported(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{}

	authCredentials := AuthCredential{
		Placement: "body",
	}
	_, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.Error(t, err, "the credential location is not supported")
}

func TestGetCredentialsFromCustomHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"x-api-key": "DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		Identifier: "X-API-KEY",
		Placement:  httputil.InCustomHeader,
	}
	cred, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromCustomHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{}

	authCredentials := AuthCredential{
		Identifier: "X-API-KEY",
		Placement:  httputil.InCustomHeader,
	}
	_, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestGetCredentialsFromAuthHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"authorization": "X-API-KEY DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		Identifier: "X-API-KEY",
		Placement:  httputil.InAuthorizationHeader,
	}
	cred, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromAuthHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"authorization": "X-API-KEY DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		Identifier: "Bearer",
		Placement:  httputil.InAuthorizationHeader,
	}
	_, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestGetCredentialsFromCookieHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "Expires=Tue, 01-Jan-2016 21:47:38 GMT; API-KEY=HumanInstrumentality"},
	}

	authCredentials := AuthCredential{
		Identifier: "API-KEY",
		Placement:  httputil.InCookie,
	}
	cred, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "HumanInstrumentality")
}

func TestGetCredentialsFromCookieHeaderFirstKey(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "API-KEY=HumanInstrumentality; Expires=Tue, 01-Jan-2016 21:47:38 GMT"},
	}

	authCredentials := AuthCredential{
		Identifier: "API-KEY",
		Placement:  httputil.InCookie,
	}
	cred, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "HumanInstrumentality")
}

func TestGetCredentialsFromCookieHeaderWithEqualSign(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "Expires=Tue, 01-Jan-2016 21:47:38 GMT; API-KEY=SHVtYW5JbnN0cnVtZW50YWxpdHk="},
	}

	authCredentials := AuthCredential{
		Identifier: "API-KEY",
		Placement:  httputil.InCookie,
	}
	cred, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "SHVtYW5JbnN0cnVtZW50YWxpdHk=")
}

func TestGetCredentialsFromCookieHeaderNoCookieHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"cookie": "Expires=Tue, 01-Jan-2016 21:47:38 GMT"},
	}

	authCredentials := AuthCredential{
		Identifier: "API-KEY",
		Placement:  httputil.InCookie,
	}
	_, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.Error(t, err, "credential not found")

}

func TestGetCredentialsFromCookieHeaderNoKeyFoundFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{},
	}

	authCredentials := AuthCredential{
		Identifier: "API-KEY",
		Placement:  httputil.InCookie,
	}
	_, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.Error(t, err, "credential not found")

}

func TestGetCredentialsFromQuerySuccess(t *testing.T) {
	// as first query param
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?api_key=DasUberApiKey",
	}

	authCredentials := AuthCredential{
		Identifier: "api_key",
		Placement:  httputil.InQuery,
	}
	cred, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")

	// as a nth query param
	httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?third_impact=true&api_key=DasUberApiKey&some=scheisse",
	}

	cred, err = authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromQueryFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?third_impact=true&some=scheisse",
	}

	authCredentials := AuthCredential{
		Identifier: "api_key",
		Placement:  httputil.InQuery,
	}
	_, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestGetCredentialsFromQueryWithSpecialCharactersInIdentifier(t *testing.T) {
	// Test that special regex characters in the identifier don't cause panics
	// This would have panicked with the old regexp.MustCompile approach
	testCases := []struct {
		name       string
		identifier string
		path       string
		wantValue  string
		wantErr    bool
	}{
		{
			name:       "identifier with brackets",
			identifier: "token[0]",
			path:       "/api?token[0]=secret123",
			wantValue:  "secret123",
			wantErr:    false,
		},
		{
			name:       "identifier with plus (URL encoded)",
			identifier: "a+b",
			path:       "/api?a%2Bb=value", // + must be encoded as %2B in query string
			wantValue:  "value",
			wantErr:    false,
		},
		{
			name:       "identifier with asterisk",
			identifier: "key*",
			path:       "/api?key*=data",
			wantValue:  "data",
			wantErr:    false,
		},
		{
			name:       "identifier with dot",
			identifier: "api.key",
			path:       "/api?api.key=token",
			wantValue:  "token",
			wantErr:    false,
		},
		{
			name:       "url encoded value",
			identifier: "redirect_uri",
			path:       "/auth?redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
			wantValue:  "https://example.com/callback",
			wantErr:    false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			httpReq := envoyServiceAuthV3.AttributeContext_HttpRequest{
				Path: tt.path,
			}
			authCredentials := AuthCredential{
				Identifier: tt.identifier,
				Placement:  httputil.InQuery,
			}

			cred, err := authCredentials.GetCredentialsFromAuthReq(&httpReq)

			if tt.wantErr {
				assert.ErrorContains(t, err, "credential not found")
			} else {
				assert.NilError(t, err)
				assert.Check(t, cred == tt.wantValue, "got %q, want %q", cred, tt.wantValue)
			}
		})
	}
}
