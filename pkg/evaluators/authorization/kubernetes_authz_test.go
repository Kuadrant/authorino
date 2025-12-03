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
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type k8sAuthorizationClientMock struct {
	k8s_client.Client
	request                           kubeAuthz.SubjectAccessReviewSpec
	subjectAccessReviewResponseStatus kubeAuthz.SubjectAccessReviewStatus
	lastCreatedSubjectAccessReview    *kubeAuthz.SubjectAccessReview
}

func (client *k8sAuthorizationClientMock) Create(ctx context.Context, obj k8s_client.Object, opts ...k8s_client.CreateOption) error {
	if sar, ok := obj.(*kubeAuthz.SubjectAccessReview); ok {
		client.request = *sar.Spec.DeepCopy()
		client.lastCreatedSubjectAccessReview = sar
		sar.Status = client.subjectAccessReviewResponseStatus
	}
	return nil
}

func (client *k8sAuthorizationClientMock) GetRequest() kubeAuthz.SubjectAccessReviewSpec {
	return client.request
}

func newKubernetesAuthz(user expressions.Value, authorizationGroups expressions.Value, resourceAttributes *KubernetesAuthzResourceAttributes, subjectAccessReviewResponseStatus kubeAuthz.SubjectAccessReviewStatus) (*KubernetesAuthz, *k8sAuthorizationClientMock) {
	mockClient := &k8sAuthorizationClientMock{
		Client:                            fake.NewClientBuilder().Build(),
		subjectAccessReviewResponseStatus: subjectAccessReviewResponseStatus,
	}
	return &KubernetesAuthz{
		User:                user,
		AuthorizationGroups: authorizationGroups,
		ResourceAttributes:  resourceAttributes,
		k8sClient:           mockClient,
	}, mockClient
}

func TestKubernetesAuthzNonResource_Allowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john", "groups":["group1","group2"]}}}`)

	request := &envoy_auth.AttributeContext_HttpRequest{Method: "GET", Path: "/hello"}
	pipelineMock.EXPECT().GetHttp().Return(request)

	kubernetesAuth, mockClient := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, &json.JSONValue{Pattern: "auth.identity.groups"}, nil, kubeAuthz.SubjectAccessReviewStatus{Allowed: true, Reason: ""})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	requestData := mockClient.GetRequest()
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

	kubernetesAuth, mockClient := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, nil, nil, kubeAuthz.SubjectAccessReviewStatus{Allowed: false, Reason: "some-reason"})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	requestData := mockClient.GetRequest()
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

	kubernetesAuth, mockClient := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, &json.JSONValue{Pattern: "auth.identity.groups"}, &KubernetesAuthzResourceAttributes{Namespace: &json.JSONValue{Static: "default"}}, kubeAuthz.SubjectAccessReviewStatus{Allowed: true, Reason: ""})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, authorized.(bool))
	assert.NilError(t, err)

	requestData := mockClient.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.DeepEqual(t, requestData.Groups, []string{"group1", "group2"})
	assert.Equal(t, requestData.ResourceAttributes.Namespace, "default")
}

func TestKubernetesAuthzResource_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`)

	kubernetesAuth, mockClient := newKubernetesAuthz(&json.JSONValue{Pattern: "auth.identity.username"}, &json.JSONValue{Static: []string{"group1", "group2"}}, &KubernetesAuthzResourceAttributes{Namespace: &json.JSONValue{Static: "default"}}, kubeAuthz.SubjectAccessReviewStatus{Allowed: false, Reason: "some-reason"})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, !authorized.(bool))
	assert.ErrorContains(t, err, "not authorized: some-reason")

	requestData := mockClient.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.DeepEqual(t, requestData.Groups, []string{"group1", "group2"})
	assert.Equal(t, requestData.ResourceAttributes.Namespace, "default")
}
