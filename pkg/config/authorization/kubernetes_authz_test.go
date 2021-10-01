package authorization

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kuadrant/authorino/pkg/common"
	mock_common "github.com/kuadrant/authorino/pkg/common/mocks"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
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

func newKubernetesAuthz(conditions []common.JSONPatternMatchingRule, user common.JSONValue, groups []string, resourceAttributes *KubernetesAuthzResourceAttributes, subjectAccessReviewResponseStatus kubeAuthz.SubjectAccessReviewStatus) *KubernetesAuthz {
	return &KubernetesAuthz{
		Conditions:         conditions,
		User:               user,
		Groups:             groups,
		ResourceAttributes: resourceAttributes,

		// mock the authorizer so we can control the response
		authorizer: &k8sAuthorizationClientMock{SubjectAccessReviewStatus: subjectAccessReviewResponseStatus},
	}
}

func TestKubernetesAuthzNonResource_Allowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	var authData interface{}
	_ = json.Unmarshal([]byte(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	request := &envoy_auth.AttributeContext_HttpRequest{Method: "GET", Path: "/hello"}
	pipelineMock.EXPECT().GetHttp().Return(request)

	kubernetesAuth := newKubernetesAuthz(
		[]common.JSONPatternMatchingRule{},
		common.JSONValue{Pattern: "auth.identity.username"},
		[]string{},
		nil,
		kubeAuthz.SubjectAccessReviewStatus{Allowed: true, Reason: ""},
	)
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.Equal(t, requestData.NonResourceAttributes.Path, "/hello")
	assert.Equal(t, requestData.NonResourceAttributes.Verb, "get")

	assert.Check(t, authorized)
	assert.NilError(t, err)
}

func TestKubernetesAuthzNonResource_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	var authData interface{}
	_ = json.Unmarshal([]byte(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	request := &envoy_auth.AttributeContext_HttpRequest{Method: "GET", Path: "/hello"}
	pipelineMock.EXPECT().GetHttp().Return(request)

	kubernetesAuth := newKubernetesAuthz(
		[]common.JSONPatternMatchingRule{},
		common.JSONValue{Pattern: "auth.identity.username"},
		[]string{},
		nil,
		kubeAuthz.SubjectAccessReviewStatus{Allowed: false, Reason: "some-reason"},
	)
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.Equal(t, requestData.NonResourceAttributes.Path, "/hello")
	assert.Equal(t, requestData.NonResourceAttributes.Verb, "get")

	assert.Check(t, !authorized)
	assert.ErrorContains(t, err, "Not authorized: some-reason")
}

func TestKubernetesAuthzResource_Allowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	var authData interface{}
	_ = json.Unmarshal([]byte(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	kubernetesAuth := newKubernetesAuthz(
		[]common.JSONPatternMatchingRule{},
		common.JSONValue{Pattern: "auth.identity.username"},
		[]string{},
		&KubernetesAuthzResourceAttributes{Namespace: common.JSONValue{Static: "default"}},
		kubeAuthz.SubjectAccessReviewStatus{Allowed: true, Reason: ""},
	)
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, authorized)
	assert.NilError(t, err)

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.Equal(t, requestData.ResourceAttributes.Namespace, "default")
}

func TestKubernetesAuthzResource_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	var authData interface{}
	_ = json.Unmarshal([]byte(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	kubernetesAuth := newKubernetesAuthz(
		[]common.JSONPatternMatchingRule{},
		common.JSONValue{Pattern: "auth.identity.username"},
		[]string{},
		&KubernetesAuthzResourceAttributes{Namespace: common.JSONValue{Static: "default"}},
		kubeAuthz.SubjectAccessReviewStatus{Allowed: false, Reason: "some-reason"},
	)
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, !authorized)
	assert.ErrorContains(t, err, "Not authorized: some-reason")

	client, _ := kubernetesAuth.authorizer.(subjectAccessReviewTestClient)
	requestData := client.GetRequest()
	assert.Equal(t, requestData.User, "john")
	assert.Equal(t, requestData.ResourceAttributes.Namespace, "default")
}

func TestKubernetesAuthzWithConditions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	var authData interface{}
	_ = json.Unmarshal([]byte(`{"context":{"request":{"http":{"method":"GET","path":"/hello"}}},"auth":{"identity":{"username":"john"}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	kubernetesAuth := newKubernetesAuthz(
		[]common.JSONPatternMatchingRule{
			{Selector: "context.request.http.method", Operator: "eq", Value: "DELETE"},
		},
		common.JSONValue{Pattern: "auth.identity.username"},
		[]string{},
		nil,
		kubeAuthz.SubjectAccessReviewStatus{Allowed: false, Reason: ""},
	)
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, authorized)
	assert.NilError(t, err)
}
