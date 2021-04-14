package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"
)

type OAuth2 struct {
	TokenIntrospectionUrl string `yaml:"tokenIntrospectionUrl"`
	TokenTypeHint         string `yaml:"tokenTypeHint,omitempty"`
	ClientID              string `yaml:"clientId"`
	ClientSecret          string `yaml:"clientSecret"`

	Credentials auth_credentials.AuthCredentials
}

func NewOAuth2Identity(tokenIntrospectionUrl string, tokenTypeHint string, clientID string, clientSecret string, creds auth_credentials.AuthCredentials) *OAuth2 {
	var tokenHint string
	if tokenTypeHint == "" {
		tokenHint = "access_token"
	} else {
		tokenHint = tokenTypeHint
	}

	return &OAuth2{
		tokenIntrospectionUrl,
		tokenHint,
		clientID,
		clientSecret,
		creds,
	}
}

func (oauth *OAuth2) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	// retrieve access token
	accessToken, err := oauth.Credentials.GetCredentialsFromReq(pipeline.GetHttp())
	if err != nil {
		return nil, err
	}

	// introspect token
	tokenIntrospectionURL, _ := url.Parse(oauth.TokenIntrospectionUrl)
	tokenIntrospectionURL.User = url.UserPassword(oauth.ClientID, oauth.ClientSecret)

	formData := url.Values{
		"token":           {accessToken},
		"token_type_hint": {oauth.TokenTypeHint},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenIntrospectionURL.String(), bytes.NewBufferString(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse the response
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	} else {
		return claims, nil
	}
}
