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

type subjectAccessReviewStatusData struct {
	allowed bool
	reason  string
}

type subjectAccessReviews struct {
	subjectAccessReviewStatusData
}

func (t *subjectAccessReviews) Create(ctx context.Context, subjectAccessReview *kubeAuthz.SubjectAccessReview, opts metav1.CreateOptions) (*kubeAuthz.SubjectAccessReview, error) {
	return &kubeAuthz.SubjectAccessReview{
		Spec: subjectAccessReview.Spec,
		Status: kubeAuthz.SubjectAccessReviewStatus{
			Allowed: t.allowed,
			Reason:  t.reason,
		},
	}, nil
}

type k8sAuthorizationClientMock struct {
	subjectAccessReviewStatusData
}

func (client *k8sAuthorizationClientMock) SubjectAccessReviews() kubeAuthzClient.SubjectAccessReviewInterface {
	return &subjectAccessReviews{
		subjectAccessReviewStatusData{
			client.allowed,
			client.reason,
		},
	}
}

func newKubernetesAuthz(user common.JSONValue, groups []string, authzClientStubbedResponse subjectAccessReviewStatusData) *KubernetesAuthz {
	return &KubernetesAuthz{
		User:   user,
		Groups: groups,

		// mock the authorizer so we can control the response
		authorizer: &k8sAuthorizationClientMock{authzClientStubbedResponse},
	}
}

func TestKubernetesAuthzUserAllowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Method: "GET", Path: "/hello"}
	pipelineMock.EXPECT().GetHttp().Return(request).AnyTimes()

	var authData interface{}
	_ = json.Unmarshal([]byte(`{"context":{},"auth":{"identity":{}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	kubernetesAuth := newKubernetesAuthz(common.JSONValue{Static: "john"}, []string{}, subjectAccessReviewStatusData{true, ""})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, authorized)
	assert.NilError(t, err)
}

func TestKubernetesAuthzUserDenied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Method: "GET", Path: "/hello"}
	pipelineMock.EXPECT().GetHttp().Return(request).AnyTimes()

	var authData interface{}
	_ = json.Unmarshal([]byte(`{"context":{},"auth":{"identity":{}}}`), &authData)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(authData)

	kubernetesAuth := newKubernetesAuthz(common.JSONValue{Static: "john"}, []string{}, subjectAccessReviewStatusData{false, "some-reason"})
	authorized, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, !authorized)
	assert.ErrorContains(t, err, "Not authorized: some-reason")
}
