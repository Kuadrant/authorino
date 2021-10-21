package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"

	kubeAuthz "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubeAuthzClient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
)

type kubernetesSubjectAccessReviewer interface {
	SubjectAccessReviews() kubeAuthzClient.SubjectAccessReviewInterface
}

func NewKubernetesAuthz(conditions []common.JSONPatternMatchingRule, user common.JSONValue, groups []string, resourceAttributes *KubernetesAuthzResourceAttributes) (*KubernetesAuthz, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &KubernetesAuthz{
		Conditions:         conditions,
		User:               user,
		Groups:             groups,
		ResourceAttributes: resourceAttributes,
		authorizer:         k8sClient.AuthorizationV1(),
	}, nil
}

type KubernetesAuthzResourceAttributes struct {
	Namespace   common.JSONValue
	Group       common.JSONValue
	Resource    common.JSONValue
	Name        common.JSONValue
	SubResource common.JSONValue
	Verb        common.JSONValue
}

type KubernetesAuthz struct {
	Conditions []common.JSONPatternMatchingRule

	User               common.JSONValue
	Groups             []string
	ResourceAttributes *KubernetesAuthzResourceAttributes

	authorizer kubernetesSubjectAccessReviewer
}

func (k *KubernetesAuthz) Call(pipeline common.AuthPipeline, ctx context.Context) (bool, error) {
	if err := common.CheckContext(ctx); err != nil {
		return false, err
	}

	data := pipeline.GetDataForAuthorization()
	dataJSON, _ := json.Marshal(data)
	dataStr := string(dataJSON)

	for _, condition := range k.Conditions {
		if match, err := condition.EvaluateFor(dataStr); err != nil {
			return false, err
		} else if !match { // skip the policy if any of the conditions does not match
			return true, nil
		}
	}

	jsonValueToStr := func(value common.JSONValue) string {
		return fmt.Sprintf("%s", value.ResolveFor(dataStr))
	}

	subjectAccessReview := kubeAuthz.SubjectAccessReview{
		Spec: kubeAuthz.SubjectAccessReviewSpec{
			User: jsonValueToStr(k.User),
		},
	}

	if k.ResourceAttributes != nil {
		resourceAttributes := k.ResourceAttributes

		subjectAccessReview.Spec.ResourceAttributes = &kubeAuthz.ResourceAttributes{
			Namespace:   jsonValueToStr(resourceAttributes.Namespace),
			Group:       jsonValueToStr(resourceAttributes.Group),
			Resource:    jsonValueToStr(resourceAttributes.Resource),
			Name:        jsonValueToStr(resourceAttributes.Name),
			Subresource: jsonValueToStr(resourceAttributes.SubResource),
			Verb:        jsonValueToStr(resourceAttributes.Verb),
		}
	} else {
		request := pipeline.GetHttp()

		subjectAccessReview.Spec.NonResourceAttributes = &kubeAuthz.NonResourceAttributes{
			Path: request.Path,
			Verb: strings.ToLower(request.Method),
		}
	}

	if len(k.Groups) > 0 {
		subjectAccessReview.Spec.Groups = k.Groups
	}

	log.FromContext(ctx).WithName("kubernetesauthz").V(1).Info("calling kubernetes subject access review api", "subjectaccessreview", subjectAccessReview)

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
