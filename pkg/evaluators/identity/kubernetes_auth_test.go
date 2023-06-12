package identity

import (
	"context"
	"encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

type kubernetesTokenReviewDataMock struct {
	requestToken  string
	authenticated bool
	audiences     []string
}

type kubernetesTokenReviewsMock struct {
	kubernetesTokenReviewDataMock
}

func (t *kubernetesTokenReviewsMock) Create(ctx context.Context, tokenReview *authv1.TokenReview, opts metav1.CreateOptions) (*authv1.TokenReview, error) {
	if t.authenticated {
		return &authv1.TokenReview{
			Spec: tokenReview.Spec,
			Status: authv1.TokenReviewStatus{
				Authenticated: true,
				User: authv1.UserInfo{
					Username: "system:serviceaccount:authorino:api-consumer",
					UID:      "eb5bcf55-6bdb-4b5b-a7ae-fbb8ad1119cb",
					Groups: []string{
						"system:serviceaccounts",
						"system:serviceaccounts:authorino",
						"system:authenticated",
					},
				},
				Audiences: t.audiences,
			},
		}, nil
	} else {
		return &authv1.TokenReview{
			Spec: tokenReview.Spec,
			Status: authv1.TokenReviewStatus{
				User:      authv1.UserInfo{},
				Audiences: t.audiences,
				Error:     "[invalid bearer token, token lookup failed]",
			},
		}, nil
	}
}

type kubernetesAuthenticationClientMock struct {
	kubernetesTokenReviewDataMock
}

func (client *kubernetesAuthenticationClientMock) TokenReviews() authenticationv1.TokenReviewInterface {
	return &kubernetesTokenReviewsMock{
		kubernetesTokenReviewDataMock{
			client.requestToken,
			client.authenticated,
			client.audiences,
		},
	}
}

func newKubernetesAuthMock(authCreds *mock_auth.MockAuthCredentials, audiences []string, token kubernetesTokenReviewDataMock) *KubernetesAuth {
	authenticator := &kubernetesAuthenticationClientMock{token}

	return &KubernetesAuth{
		authCreds,
		kubernetesAuthDetails{
			audiences,
			authenticator,
			"whatever-token-mounted-in-/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
}

func TestKubernetesTokenReviewWithOpaqueToken(t *testing.T) {
	const requestToken string = `some-opaque-token`
	const expectedIdObj string = `{"authenticated":true,"user":{"username":"system:serviceaccount:authorino:api-consumer","uid":"eb5bcf55-6bdb-4b5b-a7ae-fbb8ad1119cb","groups":["system:serviceaccounts","system:serviceaccounts:authorino","system:authenticated"]},"audiences":["echo-api"]}`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	pipelineMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuthMock(authCredsMock, []string{}, kubernetesTokenReviewDataMock{requestToken, true, []string{"echo-api"}})
	ret, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.NilError(t, err)

	claims, _ := json.Marshal(ret)
	assert.Equal(t, expectedIdObj, string(claims))
}

func TestKubernetesTokenReviewWithJWT(t *testing.T) {
	const requestToken string = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjdXY3BwMVY1cTBPOFF6aFc0U3Ywb1NtaVh4T09qTnpKV2lKN21WVXJObmcifQ.eyJhdWQiOlsiZWNoby1hcGkiXSwiZXhwIjoxNjE2NTkyMDkxLCJpYXQiOjE2MTY1OTE0OTEsImlzcyI6Imt1YmVybmV0ZXMuZGVmYXVsdC5zdmMiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXIiLCJ1aWQiOiJlYjViY2Y1NS02YmRiLTRiNWItYTdhZS1mYmI4YWQxMTE5Y2IifX0sIm5iZiI6MTYxNjU5MTQ5MSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmF1dGhvcmlubzphcGktY29uc3VtZXIifQ.Kp8pkOqFQoriumJTxtpRGJB3F26jpYVpxzXZBLbCSJKYi1CvgwdzsbVwlbbSOl5qCS62xlQCcPAyr3M56jjOjw-3_fHmQ8O8K7BcN6oDdRFRZgu5f0z6jVyi-aAEH0tieexRsPNJotenwSJn-eoCytLcIF70LNWhhmFbHNjZffFl5-Tl7blqfG60ztXmeo-N0ISoXXPnEwgV5CxWyTKDagmp0bYeCaiSszUe4YSOGmUeU9xLuM3wBHg93GFWFs3ZSQ_-mnaBnNoLBytd_nS_IOehIDdu1jPmNCJVFNpwOYxrvxisTPa--IjV_zIS5D9WR2dR6h8w8CFkdMlSFssANw`
	const expectedIdObj string = `{"authenticated":true,"user":{"username":"system:serviceaccount:authorino:api-consumer","uid":"eb5bcf55-6bdb-4b5b-a7ae-fbb8ad1119cb","groups":["system:serviceaccounts","system:serviceaccounts:authorino","system:authenticated"]},"audiences":["echo-api"]}`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	pipelineMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuthMock(authCredsMock, []string{}, kubernetesTokenReviewDataMock{requestToken, true, []string{"echo-api"}})
	ret, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.NilError(t, err)

	claims, _ := json.Marshal(ret)
	assert.Equal(t, expectedIdObj, string(claims))
}

func TestKubernetesTokenReviewUnauthenticatedToken(t *testing.T) {
	const requestToken string = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjdXY3BwMVY1cTBPOFF6aFc0U3Ywb1NtaVh4T09qTnpKV2lKN21WVXJObmcifQ.eyJhdWQiOlsiZWNoby1hcGkiXSwiZXhwIjoxNjE2NTkyMDkxLCJpYXQiOjE2MTY1OTE0OTEsImlzcyI6Imt1YmVybmV0ZXMuZGVmYXVsdC5zdmMiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXIiLCJ1aWQiOiJlYjViY2Y1NS02YmRiLTRiNWItYTdhZS1mYmI4YWQxMTE5Y2IifX0sIm5iZiI6MTYxNjU5MTQ5MSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmF1dGhvcmlubzphcGktY29uc3VtZXIifQ.Kp8pkOqFQoriumJTxtpRGJB3F26jpYVpxzXZBLbCSJKYi1CvgwdzsbVwlbbSOl5qCS62xlQCcPAyr3M56jjOjw-3_fHmQ8O8K7BcN6oDdRFRZgu5f0z6jVyi-aAEH0tieexRsPNJotenwSJn-eoCytLcIF70LNWhhmFbHNjZffFl5-Tl7blqfG60ztXmeo-N0ISoXXPnEwgV5CxWyTKDagmp0bYeCaiSszUe4YSOGmUeU9xLuM3wBHg93GFWFs3ZSQ_-mnaBnNoLBytd_nS_IOehIDdu1jPmNCJVFNpwOYxrvxisTPa--IjV_zIS5D9WR2dR6h8w8CFkdMlSFssANw`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	pipelineMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuthMock(authCredsMock, []string{}, kubernetesTokenReviewDataMock{requestToken, false, []string{"echo-api"}})
	ret, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, ret == nil)
	assert.Error(t, err, "Not authenticated")
}

func TestKubernetesTokenReviewAudiencesMatch(t *testing.T) {
	const requestToken string = `eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1vQmRRVjBhVGJ2elZOVGVEQ3JEQ1dUb1J4cGJnUzRES0JZNk1zX0M2c3cifQ.eyJhdWQiOlsiY3VzdG9tLWF1ZGllbmNlIl0sImV4cCI6MTYxNjY4NDA5OCwiaWF0IjoxNjE2NjgzNDk4LCJpc3MiOiJrdWJlcm5ldGVzLmRlZmF1bHQuc3ZjIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJhdXRob3Jpbm8iLCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYXBpLWNvbnN1bWVyIiwidWlkIjoiMWE0MTI0NjUtZWJjMi00MzcyLWE2NzMtYzIwNDBjMWQ3YmI3In19LCJuYmYiOjE2MTY2ODM0OTgsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDphdXRob3Jpbm86YXBpLWNvbnN1bWVyIn0.hXPwycVZnmcqtYUjRXCvUChFlPIk5FQpMO9-kbX6UgP2vdEftuWKZhR1FxfT6BkMzk-mfCmjBaS171i4hwl0TErnu8YDYlA4wy-L3dGSAi-ys1PAk1oEu7XaKMA7J2Amv-Xm6GdeAL5LAyTEXuvCV0kzauxqc_XX2eTqxk_54fpbQH79EHVCr1gm1R2CTvQLNitZ8k-YyHCGU4J8UxUNWQvgu-HFYHNUCIuRUbYqsCYwDgIzxXl8_3qeywK8pp316PiWFcXzJ5cOV2aeMy_xpKO-9i08R4ezT2KeHc3JlgX6BBOnh1ft60CNgPd7xk81CKEDnSMnCmc072rJslv89Q`
	const expectedIdObj string = `{"authenticated":true,"user":{"username":"system:serviceaccount:authorino:api-consumer","uid":"eb5bcf55-6bdb-4b5b-a7ae-fbb8ad1119cb","groups":["system:serviceaccounts","system:serviceaccounts:authorino","system:authenticated"]},"audiences":["custom-audience"]}`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	pipelineMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuthMock(authCredsMock, []string{"custom-audience"}, kubernetesTokenReviewDataMock{requestToken, true, []string{"custom-audience"}})
	ret, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.NilError(t, err)

	claims, _ := json.Marshal(ret)
	assert.Equal(t, expectedIdObj, string(claims))
}

func TestKubernetesTokenReviewAudiencesUnmatch(t *testing.T) {
	const requestToken string = `eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1vQmRRVjBhVGJ2elZOVGVEQ3JEQ1dUb1J4cGJnUzRES0JZNk1zX0M2c3cifQ.eyJhdWQiOlsiY3VzdG9tLWF1ZGllbmNlIl0sImV4cCI6MTYxNjY4NDA5OCwiaWF0IjoxNjE2NjgzNDk4LCJpc3MiOiJrdWJlcm5ldGVzLmRlZmF1bHQuc3ZjIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJhdXRob3Jpbm8iLCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYXBpLWNvbnN1bWVyIiwidWlkIjoiMWE0MTI0NjUtZWJjMi00MzcyLWE2NzMtYzIwNDBjMWQ3YmI3In19LCJuYmYiOjE2MTY2ODM0OTgsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDphdXRob3Jpbm86YXBpLWNvbnN1bWVyIn0.hXPwycVZnmcqtYUjRXCvUChFlPIk5FQpMO9-kbX6UgP2vdEftuWKZhR1FxfT6BkMzk-mfCmjBaS171i4hwl0TErnu8YDYlA4wy-L3dGSAi-ys1PAk1oEu7XaKMA7J2Amv-Xm6GdeAL5LAyTEXuvCV0kzauxqc_XX2eTqxk_54fpbQH79EHVCr1gm1R2CTvQLNitZ8k-YyHCGU4J8UxUNWQvgu-HFYHNUCIuRUbYqsCYwDgIzxXl8_3qeywK8pp316PiWFcXzJ5cOV2aeMy_xpKO-9i08R4ezT2KeHc3JlgX6BBOnh1ft60CNgPd7xk81CKEDnSMnCmc072rJslv89Q`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	pipelineMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuthMock(authCredsMock, []string{"expected-audience"}, kubernetesTokenReviewDataMock{requestToken, false, []string{"custom-audience"}})
	ret, err := kubernetesAuth.Call(pipelineMock, context.TODO())

	assert.Check(t, ret == nil)
	assert.Error(t, err, "Not authenticated")
}
