package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/config/identity"

	goidc "github.com/coreos/go-oidc"
)

type UserInfo struct {
	OIDC string `yaml:"oidc,omitempty"`
}

func (userinfo *UserInfo) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	// find associated oidc identity config
	var oidcIdentityConfig *identity.OIDC

	identityConfig, err := authContext.FindIdentityConfigByName(userinfo.OIDC)
	if err != nil {
		return nil, fmt.Errorf("Null OIDC object for config %v. Skipping related UserInfo metadata.", userinfo.OIDC)
	} else {
		ev, _ := identityConfig.(common.IdentityConfigEvaluator)
		oidcIdentityConfig, _ = ev.GetOIDC().(*identity.OIDC)
	}

	// discover oidc config
	// TODO: Move to a 'prepare' step and cache it (like in pkg/config/authorization/opa.go)
	provider, err := oidcIdentityConfig.NewProvider(ctx)
	if err != nil {
		return nil, err
	}

	// get access token from input
	accessToken, err := oidcIdentityConfig.Credentials.GetCredentialsFromReq(authContext.GetRequest().GetAttributes().GetRequest().GetHttp())
	if err != nil {
		return nil, err
	}

	// fetch user info
	if userInfoURL, err := userinfo.clientAuthenticatedUserInfoEndpoint(provider); err != nil {
		return nil, err
	} else {
		return fetchUserInfo(userInfoURL.String(), accessToken, ctx)
	}
}

func (userinfo *UserInfo) clientAuthenticatedUserInfoEndpoint(provider *goidc.Provider) (*url.URL, error) {
	var providerClaims map[string]interface{}
	_ = provider.Claims(&providerClaims)

	if userInfoURL, err := url.Parse(providerClaims["userinfo_endpoint"].(string)); err != nil {
		return nil, err
	} else {
		return userInfoURL, nil
	}
}

func fetchUserInfo(userInfoEndpoint string, accessToken string, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
	err = json.NewDecoder(resp.Body).Decode(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
