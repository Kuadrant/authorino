package authorization

import (
	gocontext "context"
	gojson "encoding/json"
	"fmt"
	"strings"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"

	kubeAuthz "k8s.io/api/authorization/v1"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
)

func NewKubernetesAuthz(user expressions.Value, authorizationGroups expressions.Value, resourceAttributes *KubernetesAuthzResourceAttributes, k8sClient k8s_client.Client) *KubernetesAuthz {
	return &KubernetesAuthz{
		User:                user,
		AuthorizationGroups: authorizationGroups,
		ResourceAttributes:  resourceAttributes,
		k8sClient:           k8sClient,
	}
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
	User                expressions.Value
	AuthorizationGroups expressions.Value
	ResourceAttributes  *KubernetesAuthzResourceAttributes
	k8sClient           k8s_client.Client
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
		return json.StringifyJSON(resolved)
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

	if k.AuthorizationGroups != nil {
		stringJson, err := jsonValueToStr(k.AuthorizationGroups)
		if err != nil {
			return nil, err
		}
		var resolvedGroups []string
		err = gojson.Unmarshal([]byte(stringJson), &resolvedGroups)
		if err != nil {
			return nil, err
		}
		subjectAccessReview.Spec.Groups = resolvedGroups
	}

	log.FromContext(ctx).WithName("kubernetesauthz").V(1).Info("calling kubernetes subject access review api", "subjectaccessreview", subjectAccessReview)

	if err := k.k8sClient.Create(ctx, &subjectAccessReview); err != nil {
		return false, err
	}
	return parseSubjectAccessReviewResult(&subjectAccessReview)
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
