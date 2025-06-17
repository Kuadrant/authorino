package metadata

import (
	gocontext "context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"

	"go.opentelemetry.io/otel"
	otel_propagation "go.opentelemetry.io/otel/propagation"
)

type UserInfo struct {
	OpenIdConfig     auth.OpenIdConfigStore
	UserInfoEndpoint string
}

func NewUserInfo(openIdConfigStore auth.OpenIdConfigStore, userInfoEndpoint string) *UserInfo {
	return &UserInfo{
		OpenIdConfig:     openIdConfigStore,
		UserInfoEndpoint: userInfoEndpoint,
	}
}

func (u *UserInfo) Call(pipeline auth.AuthPipeline, parentCtx gocontext.Context) (interface{}, error) {
	ctx := log.IntoContext(parentCtx, log.FromContext(parentCtx).WithName("userinfo"))

	userInfoEndpoint := u.UserInfoEndpoint

	resolvedIdentity, _ := pipeline.GetResolvedIdentity()
	resolvedIdentityEvaluator, _ := resolvedIdentity.(auth.IdentityConfigEvaluator)

	if u.OpenIdConfig != nil {
		issuer, err := u.OpenIdConfig.GetOpenIdUrl(ctx, "issuer")
		if err != nil {
			return nil, err
		}

		// check if the resolved identity is also an oidc config whose userinfo endpoint matches the one of the userinfo metadata
		// skip the useinfo metadata otherwise
		if resolvedIdentityOidc := resolvedIdentityEvaluator.GetOpenIdConfig(); resolvedIdentityOidc != nil {
			resolvedIdentityIssuer, err := resolvedIdentityOidc.GetOpenIdUrl(ctx, "issuer")
			if err != nil {
				return nil, err
			}
			if issuer.String() != resolvedIdentityIssuer.String() {
				return nil, fmt.Errorf("missing identity for oidc issuer %v. skipping related userinfo metadata", issuer.String())
			}
		} else {
			return nil, fmt.Errorf("missing identity for oidc issuer %v. skipping related userinfo metadata", issuer.String())
		}

		// use the userinfo endpoint from the associated openid config
		userInfoUrl, err := u.OpenIdConfig.GetOpenIdUrl(ctx, "userinfo_endpoint")
		if err != nil {
			return nil, err
		}
		userInfoEndpoint = userInfoUrl.String()
	}

	// get access token from the request
	accessToken, err := resolvedIdentityEvaluator.GetAuthCredentials().GetCredentialsFromReq(pipeline.GetHttp())
	if err != nil {
		return nil, err
	}

	// fetch user info
	return fetchUserInfo(userInfoEndpoint, accessToken, ctx)
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

	otel.GetTextMapPropagator().Inject(ctx, otel_propagation.HeaderCarrier(req.Header))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// parse the response
	var claims map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
