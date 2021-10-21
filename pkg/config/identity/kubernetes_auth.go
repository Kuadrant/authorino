package identity

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"

	jwt "github.com/dgrijalva/jwt-go"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

type kubernetesTokenReviewer interface {
	TokenReviews() authenticationv1.TokenReviewInterface
}

type kubernetesAuthDetails struct {
	audiences     []string
	authenticator kubernetesTokenReviewer
	serviceToken  string
}

type KubernetesAuth struct {
	auth_credentials.AuthCredentials
	kubernetesAuthDetails
}

func NewKubernetesAuthIdentity(authCred auth_credentials.AuthCredentials, audiences []string) (*KubernetesAuth, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &KubernetesAuth{
		authCred,
		kubernetesAuthDetails{
			audiences,
			k8sClient.AuthenticationV1(),
			config.BearerToken,
		},
	}, nil
}

func (kubeAuth *KubernetesAuth) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	request := pipeline.GetHttp()
	if reqToken, err := kubeAuth.GetCredentialsFromReq(request); err != nil {
		return nil, err
	} else {
		tr := authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{
				Token:     reqToken,
				Audiences: kubeAuth.audiencesWithDefault(request.Host),
			},
		}

		log.FromContext(ctx).WithName("kubernetesauth").V(1).Info("calling kubernetes token review api", "tokenreview", tr)

		if result, err := kubeAuth.authenticator.TokenReviews().Create(ctx, &tr, metav1.CreateOptions{}); err != nil {
			return nil, err
		} else {
			return parseTokenReviewResult(result)
		}
	}
}

func (kubeAuth *KubernetesAuth) audiencesWithDefault(defaultAudience string) []string {
	if len(kubeAuth.audiences) > 0 {
		return kubeAuth.audiences
	} else {
		return []string{defaultAudience}
	}
}

func parseTokenReviewResult(tokenReview *authv1.TokenReview) (interface{}, error) {
	tokenReviewStatus := tokenReview.Status
	if tokenReviewStatus.Authenticated {
		// returns the jwt claims (if the token is in fact a jwt); otherwise, returns the "user" in the TokenReview status
		if claims, err := decodeTrustedJWT(tokenReview.Spec.Token); err == nil {
			return claims, nil
		} else {
			return tokenReviewStatus.User, nil
		}
	} else {
		return nil, fmt.Errorf("Not authenticated")
	}
}

func decodeTrustedJWT(rawToken string) (jwt.Claims, error) {
	claims := jwt.MapClaims{}
	if token, _, err := new(jwt.Parser).ParseUnverified(rawToken, claims); err != nil { // we don't care about verifying the jwt because it has been authenticated ("reviewed") already
		return nil, err
	} else {
		return token.Claims, nil
	}
}
