package oauth2

import (
	"context"
	"net/url"
	"sync"

	httputil "github.com/kuadrant/authorino/pkg/http"
	gooauth2 "golang.org/x/oauth2"
	gooauth2clientcredentials "golang.org/x/oauth2/clientcredentials"
)

func NewClientCredentialsConfig(tokenURL, clientID, clientSecret string, scopes []string, extraParams map[string]string, timeout *int) *ClientCredentials {
	params := url.Values{}
	for k, v := range extraParams {
		params.Set(k, v)
	}
	return &ClientCredentials{
		Config: &gooauth2clientcredentials.Config{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			TokenURL:       tokenURL,
			Scopes:         scopes,
			EndpointParams: params,
		},
		Timeout: timeout,
	}
}

type ClientCredentials struct {
	*gooauth2clientcredentials.Config
	Timeout *int

	mu    sync.RWMutex
	token *gooauth2.Token
}

// ClientCredentialsToken fetches an OAuth2 token using client credentials flow.
// Uses the timeout configured in the ClientCredentials struct.
func (c *ClientCredentials) ClientCredentialsToken(ctx context.Context, force bool) (*gooauth2.Token, error) {
	c.mu.RLock()
	if c.token != nil && c.token.Valid() && !force {
		defer c.mu.RUnlock()
		return c.token, nil
	}
	c.mu.RUnlock()

	// Inject custom HTTP client with timeout into context
	// The oauth2 library will use this client for token requests
	httpClient := httputil.NewClient(c.Timeout)
	ctx = context.WithValue(ctx, gooauth2.HTTPClient, httpClient)

	token, err := c.Token(ctx)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	return c.token, nil
}
