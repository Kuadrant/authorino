package oauth2

import (
	"context"
	"net/url"
	"sync"

	gooauth2 "golang.org/x/oauth2"
	gooauth2clientcredentials "golang.org/x/oauth2/clientcredentials"
)

func NewClientCredentialsConfig(tokenURL, clientID, clientSecret string, scopes []string, extraParams map[string]string) *ClientCredentials {
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
	}
}

type ClientCredentials struct {
	*gooauth2clientcredentials.Config

	mu    sync.RWMutex
	token *gooauth2.Token
}

func (c *ClientCredentials) ClientCredentialsToken(ctx context.Context, force bool) (*gooauth2.Token, error) {
	c.mu.RLock()
	if c.token != nil && c.token.Valid() && !force {
		defer c.mu.RUnlock()
		return c.token, nil
	}
	c.mu.RUnlock()

	token, err := c.Token(ctx)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	return c.token, nil
}
