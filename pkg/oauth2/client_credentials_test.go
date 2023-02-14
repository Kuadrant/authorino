package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/kuadrant/authorino/pkg/httptest"
	"gotest.tools/assert"
)

const testOAuth2ServerHost string = "127.0.0.1:9011"

func TestClientCredentials(t *testing.T) {
	nonce := 0
	oauth2Server := httptest.NewHttpServerMock(testOAuth2ServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/token": func() httptest.HttpServerMockResponse {
			nonce = nonce + 1
			return httptest.HttpServerMockResponse{
				Status:  http.StatusOK,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    fmt.Sprintf(`{"access_token":"xyz-%d","token_type":"Bearer","expires_in":300}`, nonce), // token expires in 5 min
			}
		},
	})
	defer oauth2Server.Close()

	tokenUrl := "http://" + testOAuth2ServerHost + "/token"
	oauthConfig := NewClientCredentialsConfig(tokenUrl, "foo", "secret", []string{}, map[string]string{})

	token, err := oauthConfig.ClientCredentialsToken(context.TODO(), false)
	assert.NilError(t, err)
	assert.Equal(t, token.AccessToken, "xyz-1")

	token, err = oauthConfig.ClientCredentialsToken(context.TODO(), false)
	assert.NilError(t, err)
	assert.Equal(t, token.AccessToken, "xyz-1")

	token, err = oauthConfig.ClientCredentialsToken(context.TODO(), true)
	assert.NilError(t, err)
	assert.Equal(t, token.AccessToken, "xyz-2")

	token, err = oauthConfig.ClientCredentialsToken(context.TODO(), true)
	assert.NilError(t, err)
	assert.Equal(t, token.AccessToken, "xyz-3")

	token, err = oauthConfig.ClientCredentialsToken(context.TODO(), false)
	assert.NilError(t, err)
	assert.Equal(t, token.AccessToken, "xyz-3")
}

func TestClientCredentialsTokenExpired(t *testing.T) {
	nonce := 0
	oauth2Server := httptest.NewHttpServerMock(testOAuth2ServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/token": func() httptest.HttpServerMockResponse {
			nonce = nonce + 1
			return httptest.HttpServerMockResponse{
				Status:  http.StatusOK,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    fmt.Sprintf(`{"access_token":"xyz-%d","token_type":"Bearer","expires_in":-1}`, nonce),
			}
		},
	})
	defer oauth2Server.Close()

	tokenUrl := "http://" + testOAuth2ServerHost + "/token"
	oauthConfig := NewClientCredentialsConfig(tokenUrl, "foo", "secret", []string{}, map[string]string{})

	token, err := oauthConfig.ClientCredentialsToken(context.TODO(), true)
	assert.NilError(t, err)
	assert.Equal(t, token.AccessToken, "xyz-1")

	// because the token is expired, even without forcing the fetching of a new token, it will do it anyway
	token, err = oauthConfig.ClientCredentialsToken(context.TODO(), false)
	assert.NilError(t, err)
	assert.Equal(t, token.AccessToken, "xyz-2")
}
