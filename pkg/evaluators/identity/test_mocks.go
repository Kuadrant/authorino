package identity

import (
	"context"
	"fmt"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	k8s "k8s.io/api/core/v1"
	k8s_runtime "k8s.io/apimachinery/pkg/runtime"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
	k8s_fake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	gomock "github.com/golang/mock/gomock"
)

func mockK8sClient(initObjs ...k8s_runtime.Object) k8s_client.WithWatch {
	scheme := k8s_runtime.NewScheme()
	_ = k8s.AddToScheme(scheme)
	return k8s_fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(initObjs...).Build()
}

func mockAuthPipeline(ctrl *gomock.Controller) (pipelineMock *mock_auth.MockAuthPipeline) {
	pipelineMock = mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetHttp().Return(nil)
	return
}

type flawedAPIkeyK8sClient struct{}

func (k *flawedAPIkeyK8sClient) Get(_ context.Context, _ k8s_client.ObjectKey, _ k8s_client.Object) error {
	return nil
}

func (k *flawedAPIkeyK8sClient) List(_ context.Context, list k8s_client.ObjectList, _ ...k8s_client.ListOption) error {
	return fmt.Errorf("something terribly wrong happened")
}
