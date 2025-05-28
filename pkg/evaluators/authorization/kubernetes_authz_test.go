package authorization

import (
	"context"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/json"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	kubeAuthz "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeAuthzClient "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

type subjectAccessReviewTestClient interface {
	SetRequest(kubeAuthz.SubjectAccessReviewSpec)
	GetRequest() kubeAuthz.SubjectAccessReviewSpec
}

type subjectAccessReviews struct {
	client subjectAccessReviewTestClient
	kubeAuthz.SubjectAccessReviewStatus
}

func (t *subjectAccessReviews) Create(ctx context.Context, subjectAccessReview *kubeAuthz.SubjectAccessReview, opts metav1.CreateOptions) (*kubeAuthz.SubjectAccessReview, error) {
	// copies the actual request data back so it can be inspected
	t.client.SetRequest(subjectAccessReview.Spec)

	return &kubeAuthz.SubjectAccessReview{
		Spec: subjectAccessReview.Spec,
		Status: kubeAuthz.SubjectAccessReviewStatus{
			Allowed: t.Allowed,
			Reason:  t.Reason,
		},
	}, nil
}

type k8sAuthorizationClientMock struct {
	request kubeAuthz.SubjectAccessReviewSpec
	kubeAuthz.SubjectAccessReviewStatus
}

func (client *k8sAuthorizationClientMock) SubjectAccessReviews() kubeAuthzClient.SubjectAccessReviewInterface {
	return &subjectAccessReviews{
		client,
		client.SubjectAccessReviewStatus,
	}
}

func (client *k8sAuthorizationClientMock) SetRequest(req kubeAuthz.SubjectAccessReviewSpec) {
	client.request = *req.DeepCopy()
}

func (client *k8sAuthorizationClientMock) GetRequest() kubeAuthz.SubjectAccessReviewSpec {
	return client.request
}

func newKubernetesAuthz(user expressions.Value, authorizationGroups expressions.Value, resourceAttributes *KubernetesAuthzResourceAttributes, subjectAccessReviewResponseStatus kubeAuthz.SubjectAccessReviewStatus) *KubernetesAuthz {
	return &KubernetesAuthz{
		User:                user,
		AuthorizationGroups: authorizationGroups,
		ResourceAttributes:  resourceAttributes,

		// mock the authorizer so we can control the response
		authorizer: &k8sAuthorizationClientMock{SubjectAccessReviewStatus: subjectAccessReviewResponseStatus},
	}
}

func TestKubernetesAuthzNonResource_Allowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john", "groups":["group1","group2"]}}}`)

	request := &envoy_auth.AttributeContext_HttpRequest{Method: "GET", Path: "/hello"}
	pipelineMock.EXPECT().GetHttp().Return(request)

	kubernetesAuth := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, &json.JSONValue{Pattern: "auth.identity.groups"}, nil, kubeAuthz.SubjectAccessReviewStatus{Allowed: true, Reason: ""})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.DeepEqual(t, requestData.Groups, []string{"group1", "group2"})
	assert.Equal(t, requestData.NonResourceAttributes.Path, "/hello")
	assert.Equal(t, requestData.NonResourceAttributes.Verb, "get")

	assert.Check(t, authorized.(bool))
	assert.NilError(t, err)
}

func TestKubernetesAuthzNonResource_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`)

	request := &envoy_auth.AttributeContext_HttpRequest{Method: "GET", Path: "/hello"}
	pipelineMock.EXPECT().GetHttp().Return(request)

	kubernetesAuth := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, nil, nil, kubeAuthz.SubjectAccessReviewStatus{Allowed: false, Reason: "some-reason"})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.Assert(t, is.Len(requestData.Groups, 0))
	assert.Equal(t, requestData.NonResourceAttributes.Path, "/hello")
	assert.Equal(t, requestData.NonResourceAttributes.Verb, "get")

	assert.Check(t, !authorized.(bool))
	assert.ErrorContains(t, err, "not authorized: some-reason")
}

func TestKubernetesAuthzResource_Allowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john", "groups":["group1","group2"]}}}`)

	kubernetesAuth := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, &json.JSONValue{Pattern: "auth.identity.groups"}, &KubernetesAuthzResourceAttributes{Namespace: &json.JSONValue{Static: "default"}}, kubeAuthz.SubjectAccessReviewStatus{Allowed: true, Reason: ""})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, authorized.(bool))
	assert.NilError(t, err)

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.DeepEqual(t, requestData.Groups, []string{"group1", "group2"})
	assert.Equal(t, requestData.ResourceAttributes.Namespace, "default")
}

func TestKubernetesAuthzResource_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`)

	kubernetesAuth := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, &json.JSONValue{Static: []string{"group1", "group2"}}, &KubernetesAuthzResourceAttributes{Namespace: &json.JSONValue{Static: "default"}}, kubeAuthz.SubjectAccessReviewStatus{Allowed: false, Reason: "some-reason"})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, !authorized.(bool))
	assert.ErrorContains(t, err, "not authorized: some-reason")

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.DeepEqual(t, requestData.Groups, []string{"group1", "group2"})
	assert.Equal(t, requestData.ResourceAttributes.Namespace, "default")
}
