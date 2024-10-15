package authorization

import (
	gocontext "context"
	"fmt"
	"strings"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/log"

	kubeAuthz "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubeAuthzClient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
)

type kubernetesSubjectAccessReviewer interface {
	SubjectAccessReviews() kubeAuthzClient.SubjectAccessReviewInterface
}

func NewKubernetesAuthz(user expressions.Value, groups []string, resourceAttributes *KubernetesAuthzResourceAttributes) (*KubernetesAuthz, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &KubernetesAuthz{
		User:               user,
		Groups:             groups,
		ResourceAttributes: resourceAttributes,
		authorizer:         k8sClient.AuthorizationV1(),
	}, nil
}

type KubernetesAuthzResourceAttributes struct {
	Namespace   expressions.Value
	Group       expressions.Value
	Resource    expressions.Value
	Name        expressions.Value
	SubResource expressions.Value
	Verb        expressions.Value
}

type KubernetesAuthz struct {
	User               expressions.Value
	Groups             []string
	ResourceAttributes *KubernetesAuthzResourceAttributes

	authorizer kubernetesSubjectAccessReviewer
}

func (k *KubernetesAuthz) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	if err := context.CheckContext(ctx); err != nil {
		return false, err
	}

	authJSON := pipeline.GetAuthorizationJSON()
	jsonValueToStr := func(value expressions.Value) (string, error) {
		if value == nil {
			return "", nil
		}
		resolved, err := value.ResolveFor(authJSON)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s", resolved), nil
	}

	user, err := jsonValueToStr(k.User)
	if err != nil {
		return nil, err
	}
	subjectAccessReview := kubeAuthz.SubjectAccessReview{
		Spec: kubeAuthz.SubjectAccessReviewSpec{
			User: user,
		},
	}

	if k.ResourceAttributes != nil {
		resourceAttributes := k.ResourceAttributes

		namespace, err := jsonValueToStr(resourceAttributes.Namespace)
		if err != nil {
			return nil, err
		}
		group, err := jsonValueToStr(resourceAttributes.Group)
		if err != nil {
			return nil, err
		}
		resource, err := jsonValueToStr(resourceAttributes.Resource)
		if err != nil {
			return nil, err
		}
		name, err := jsonValueToStr(resourceAttributes.Name)
		if err != nil {
			return nil, err
		}
		subresource, err := jsonValueToStr(resourceAttributes.SubResource)
		if err != nil {
			return nil, err
		}
		verb, err := jsonValueToStr(resourceAttributes.Verb)
		if err != nil {
			return nil, err
		}
		subjectAccessReview.Spec.ResourceAttributes = &kubeAuthz.ResourceAttributes{
			Namespace:   namespace,
			Group:       group,
			Resource:    resource,
			Name:        name,
			Subresource: subresource,
			Verb:        verb,
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
		return false, fmt.Errorf("not authorized: %s", reason)
	}
}
