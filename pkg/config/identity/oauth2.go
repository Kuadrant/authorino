package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/log"
)

type OAuth2 struct {
	auth.AuthCredentials

	TokenIntrospectionUrl string `yaml:"tokenIntrospectionUrl"`
	TokenTypeHint         string `yaml:"tokenTypeHint,omitempty"`
	ClientID              string `yaml:"clientId"`
	ClientSecret          string `yaml:"clientSecret"`
}

func NewOAuth2Identity(tokenIntrospectionUrl string, tokenTypeHint string, clientID string, clientSecret string, creds auth.AuthCredentials) *OAuth2 {
	var tokenHint string
	if tokenTypeHint == "" {
		tokenHint = "access_token"
	} else {
		tokenHint = tokenTypeHint
	}

	return &OAuth2{
		creds,
		tokenIntrospectionUrl,
		tokenHint,
		clientID,
		clientSecret,
	}
}

func (oauth *OAuth2) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	// retrieve access token
	accessToken, err := oauth.GetCredentialsFromReq(pipeline.GetHttp())
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
	encodedFormData := formData.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", tokenIntrospectionURL.String(), bytes.NewBufferString(encodedFormData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	log.FromContext(ctx).WithName("oauth2").V(1).Info("sending token introspection request", "url", tokenIntrospectionURL.String(), "data", encodedFormData)

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
		if claims["active"].(bool) {
			return claims, nil
		} else {
			return nil, fmt.Errorf("token is not active")
		}
	}
}
