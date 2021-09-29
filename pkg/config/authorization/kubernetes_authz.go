package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kuadrant/authorino/pkg/common"

	kubeAuthz "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubeAuthzClient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
)

type kubernetesSubjectAccessReviewer interface {
	SubjectAccessReviews() kubeAuthzClient.SubjectAccessReviewInterface
}

func NewKubernetesAuthz(user common.JSONValue, groups []string) (*KubernetesAuthz, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &KubernetesAuthz{
		User:       user,
		Groups:     groups,
		authorizer: k8sClient.AuthorizationV1(),
	}, nil
}

type KubernetesAuthz struct {
	User   common.JSONValue
	Groups []string

	authorizer kubernetesSubjectAccessReviewer
}

func (k *KubernetesAuthz) Call(pipeline common.AuthPipeline, ctx context.Context) (bool, error) {
	if err := common.CheckContext(ctx); err != nil {
		return false, err
	}

	request := pipeline.GetHttp()
	path := request.Path
	verb := strings.ToLower(request.Method)

	data := pipeline.GetDataForAuthorization()
	dataJSON, _ := json.Marshal(data)
	dataStr := string(dataJSON)
	user := fmt.Sprintf("%s", k.User.ResolveFor(dataStr))

	subjectAccessReview := kubeAuthz.SubjectAccessReview{
		Spec: kubeAuthz.SubjectAccessReviewSpec{
			User: user,
			NonResourceAttributes: &kubeAuthz.NonResourceAttributes{
				Path: path,
				Verb: verb,
			},
		},
	}

	if len(k.Groups) > 0 {
		subjectAccessReview.Spec.Groups = k.Groups
	}

	if result, err := k.authorizer.SubjectAccessReviews().Create(ctx, &subjectAccessReview, metav1.CreateOptions{}); err != nil {
		return false, err
	} else {
		return parseSubjectAccessReviewResult(result)
	}
}

func parseSubjectAccessReviewResult(subjectAccessReview *kubeAuthz.SubjectAccessReview) (bool, error) {
	status := subjectAccessReview.Status
	if status.Allowed {
		return true, nil
	} else {
		reason := status.Reason
		if reason == "" {
			reason = "unknown reason"
		}
		return false, fmt.Errorf("Not authorized: %s", reason)
	}
}