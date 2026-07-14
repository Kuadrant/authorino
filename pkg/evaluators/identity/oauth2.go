package identity

import (
	"bytes"
	gocontext "context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"

	"go.opentelemetry.io/otel"
	otel_propagation "go.opentelemetry.io/otel/propagation"
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

func (oauth *OAuth2) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	if err := context.CheckContext(ctx); err != nil {
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

	log.FromContext(ctx).WithName("oauth2").V(1).Info("sending token introspection request", "url", log.RedactedURL(tokenIntrospectionURL), "data", log.RedactedFormData(encodedFormData))

	otel.GetTextMapPropagator().Inject(ctx, otel_propagation.HeaderCarrier(req.Header))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// a non-200 response (e.g. invalid client credentials) is not a valid introspection
	// result and may not carry the RFC 7662 "active" field; treat it as an error instead
	// of attempting to parse it as a successful introspection response.
	// The returned error only carries the status, since it is surfaced to the client (via
	// the X-Ext-Auth-Reason header) and logged; the response body may contain data from the
	// auth server and is only logged at debug level.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.FromContext(ctx).WithName("oauth2").V(1).Info("token introspection request failed", "status", resp.Status, "response", string(body))
		return nil, fmt.Errorf("token introspection request failed: %s", resp.Status)
	}

	// parse the response
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	} else {
		active, ok := claims["active"].(bool)
		if !ok {
			return nil, fmt.Errorf("invalid token introspection response: missing or non-boolean \"active\" field")
		}
		if active {
			return claims, nil
		} else {
			return nil, fmt.Errorf("token is not active")
		}
	}
}
