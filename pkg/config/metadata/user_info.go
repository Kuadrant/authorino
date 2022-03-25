package metadata

import (
	gocontext "context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/config/identity"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"
)

type UserInfo struct {
	OIDC *identity.OIDC `yaml:"oidc,omitempty"`
}

func (userinfo *UserInfo) Call(pipeline auth.AuthPipeline, parentCtx gocontext.Context) (interface{}, error) {
	ctx := log.IntoContext(parentCtx, log.FromContext(parentCtx).WithName("userinfo"))
	oidc := userinfo.OIDC

	// check if corresponding oidc identity was resolved
	resolvedIdentity, _ := pipeline.GetResolvedIdentity()
	identityEvaluator, _ := resolvedIdentity.(auth.IdentityConfigEvaluator)
	if resolvedOIDC, _ := identityEvaluator.GetOIDC().(*identity.OIDC); resolvedOIDC == nil || resolvedOIDC.Endpoint != oidc.Endpoint {
		return nil, fmt.Errorf("Missing identity for OIDC issuer %v. Skipping related UserInfo metadata.", oidc.Endpoint)
	}

	// get access token from input
	accessToken, err := oidc.GetCredentialsFromReq(pipeline.GetHttp())
	if err != nil {
		return nil, err
	}

	// fetch user info
	if userInfoURL, err := oidc.GetURL("userinfo_endpoint", ctx); err != nil {
		return nil, err
	} else {
		return fetchUserInfo(userInfoURL.String(), accessToken, ctx)
	}
}

func fetchUserInfo(userInfoEndpoint string, accessToken string, ctx gocontext.Context) (interface{}, error) {
	if err := context.CheckContext(ctx); err != nil {
		return nil, err
	}

	log.FromContext(ctx).V(1).Info("fetching user info", "endpoint", userInfoEndpoint)

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
