package identity

import (
	gocontext "context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"

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
	auth.AuthCredentials
	kubernetesAuthDetails
}

func NewKubernetesAuthIdentity(authCred auth.AuthCredentials, audiences []string) (*KubernetesAuth, error) {
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

func (kubeAuth *KubernetesAuth) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	if err := context.CheckContext(ctx); err != nil {
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
		return tokenReviewStatus, nil
	} else {
		return nil, fmt.Errorf("Not authenticated")
	}
}
