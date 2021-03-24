package identity

import (
	"context"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"

	jwt "github.com/dgrijalva/jwt-go"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

type kubernetesAuthDetails struct {
	authenticator authenticationv1.AuthenticationV1Interface
	serviceToken  string
}

type KubernetesAuth struct {
	auth_credentials.AuthCredentials
	kubernetesAuthDetails
}

func NewKubernetesAuthIdentity(authCred auth_credentials.AuthCredentials) *KubernetesAuth {
	config, _ := rest.InClusterConfig()
	k8sClient, _ := kubernetes.NewForConfig(config)

	return &KubernetesAuth{
		authCred,
		kubernetesAuthDetails{
			k8sClient.AuthenticationV1(),
			config.BearerToken,
		},
	}
}

func (kubeAuth *KubernetesAuth) Call(authCtx common.AuthContext, ctx context.Context) (interface{}, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	request := authCtx.GetHttp()
	if reqToken, err := kubeAuth.GetCredentialsFromReq(request); err != nil {
		return nil, err
	} else {
		tr := authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{
				Token: reqToken,
				Audiences: []string{
					request.Host,
				},
			},
		}

		if result, err := kubeAuth.authenticator.TokenReviews().Create(ctx, &tr, metav1.CreateOptions{}); err != nil {
			return nil, err
		} else {
			resultStatus := result.Status
			if resultStatus.Authenticated {
				claims := jwt.MapClaims{}
				// returns the jwt claims (if the token is in fact a jwt); otherwise, returns the "user" in the TokenReview status
				if token, _, err := new(jwt.Parser).ParseUnverified(reqToken, claims); err != nil { // we don't care about verifying the jwt because it has been authenticated ("reviewed") already
					return resultStatus.User, nil
				} else {
					return token.Claims, nil
				}
			} else {
				return nil, fmt.Errorf("Not authenticated")
			}
		}
	}
}
