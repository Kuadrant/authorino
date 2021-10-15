package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config/identity"
)

var userInfoLogger = log.WithName("metadata").WithName("userinfo").V(1)

type UserInfo struct {
	OIDC *identity.OIDC `yaml:"oidc,omitempty"`
}

func (userinfo *UserInfo) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	oidc := userinfo.OIDC

	// check if corresponding oidc identity was resolved
	resolvedIdentity, _ := pipeline.GetResolvedIdentity()
	identityEvaluator, _ := resolvedIdentity.(common.IdentityConfigEvaluator)
	if resolvedOIDC, _ := identityEvaluator.GetOIDC().(*identity.OIDC); resolvedOIDC == nil || resolvedOIDC.Endpoint != oidc.Endpoint {
		return nil, fmt.Errorf("Missing identity for OIDC issuer %v. Skipping related UserInfo metadata.", oidc.Endpoint)
	}

	// get access token from input
	accessToken, err := oidc.GetCredentialsFromReq(pipeline.GetHttp())
	if err != nil {
		return nil, err
	}

	// fetch user info
	if userInfoURL, err := oidc.GetURL("userinfo_endpoint"); err != nil {
		return nil, err
	} else {
		return fetchUserInfo(userInfoURL.String(), accessToken, ctx)
	}
}

func fetchUserInfo(userInfoEndpoint string, accessToken string, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	userInfoLogger.Info("fetching user info", "endpoint", userInfoEndpoint)

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
