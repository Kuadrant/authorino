package identity

import (
	gocontext "context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"

	authv1 "k8s.io/api/authentication/v1"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
)

type KubernetesAuth struct {
	auth.AuthCredentials
	audiences []string
	k8sClient k8s_client.Client
}

func NewKubernetesAuthIdentity(authCred auth.AuthCredentials, audiences []string, k8sClient k8s_client.Client) *KubernetesAuth {
	return &KubernetesAuth{
		AuthCredentials: authCred,
		audiences:       audiences,
		k8sClient:       k8sClient,
	}
}

func (kubeAuth *KubernetesAuth) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	if err := context.CheckContext(ctx); err != nil {
		return nil, err
	}

	request := pipeline.GetHttp()
	if reqToken, err := kubeAuth.GetCredentialsFromReq(request); err != nil {
		return nil, err
	} else {
		tr := &authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{
				Token:     reqToken,
				Audiences: kubeAuth.audiencesWithDefault(request.Host),
			},
		}

		log.FromContext(ctx).WithName("kubernetesauth").V(1).Info("calling kubernetes token review api", "tokenreview", tr)

		if err := kubeAuth.k8sClient.Create(ctx, tr); err != nil {
			return nil, err
		}
		return parseTokenReviewResult(tr)
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
		return nil, fmt.Errorf("not authenticated")
	}
}
