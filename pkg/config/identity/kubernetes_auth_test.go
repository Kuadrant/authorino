package identity

import (
	"context"
	"encoding/json"
	"testing"

	mock_auth_credentials "github.com/3scale-labs/authorino/pkg/common/auth_credentials/mocks"
	mock_common "github.com/3scale-labs/authorino/pkg/common/mocks"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

type authenticatorClientMock struct{}

func (client *authenticatorClientMock) GetRateLimiter() flowcontrol.RateLimiter {
	return nil
}

func (client *authenticatorClientMock) Verb(_ string) *rest.Request {
	return nil
}

func (client *authenticatorClientMock) Post() *rest.Request {
	return nil
}

func (client *authenticatorClientMock) Put() *rest.Request {
	return nil
}

func (client *authenticatorClientMock) Patch(_ types.PatchType) *rest.Request {
	return nil
}
func (client *authenticatorClientMock) Get() *rest.Request {
	return nil
}

func (client *authenticatorClientMock) Delete() *rest.Request {
	return nil
}

func (client *authenticatorClientMock) APIVersion() schema.GroupVersion {
	return schema.GroupVersion{}
}

type tokenReviewData struct {
	requestToken  string
	authenticated bool
}

type tokenReviews struct {
	tokenReviewData
}

func (t *tokenReviews) Create(ctx context.Context, tokenReview *authv1.TokenReview, opts metav1.CreateOptions) (*authv1.TokenReview, error) {
	audiences := []string{"echo-api"}

	return &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     t.requestToken,
			Audiences: audiences,
		},
		Status: authv1.TokenReviewStatus{
			Authenticated: t.authenticated,
			User: authv1.UserInfo{
				Username: "system:serviceaccount:authorino:api-consumer-sa",
				UID:      "0632367e-2455-44fb-bd01-3cf5b5f4a34b",
				Groups: []string{
					"system:serviceaccounts",
					"system:serviceaccounts:authorino",
					"system:authenticated",
				},
			},
			Audiences: audiences,
		},
	}, nil
}

type k8sAuthenticationClientMock struct {
	tokenReviewData
}

func (client *k8sAuthenticationClientMock) TokenReviews() authenticationv1.TokenReviewInterface {
	return &tokenReviews{
		tokenReviewData{
			client.requestToken,
			client.authenticated,
		},
	}
}

func (client *k8sAuthenticationClientMock) RESTClient() rest.Interface {
	return &authenticatorClientMock{}
}

func newKubernetesAuth(authCreds *mock_auth_credentials.MockAuthCredentials, token tokenReviewData) *KubernetesAuth {
	authenticator := &k8sAuthenticationClientMock{token}

	return &KubernetesAuth{
		authCreds,
		kubernetesAuthDetails{
			authenticator,
			"whatever-token-mounted-in-/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
	}
}

func TestAuthenticatedToken(t *testing.T) {
	const requestToken string = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjdXY3BwMVY1cTBPOFF6aFc0U3Ywb1NtaVh4T09qTnpKV2lKN21WVXJObmcifQ.eyJhdWQiOlsiZWNoby1hcGkiXSwiZXhwIjoxNjE2NTkyMDkxLCJpYXQiOjE2MTY1OTE0OTEsImlzcyI6Imt1YmVybmV0ZXMuZGVmYXVsdC5zdmMiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXIiLCJ1aWQiOiJlYjViY2Y1NS02YmRiLTRiNWItYTdhZS1mYmI4YWQxMTE5Y2IifX0sIm5iZiI6MTYxNjU5MTQ5MSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmF1dGhvcmlubzphcGktY29uc3VtZXIifQ.Kp8pkOqFQoriumJTxtpRGJB3F26jpYVpxzXZBLbCSJKYi1CvgwdzsbVwlbbSOl5qCS62xlQCcPAyr3M56jjOjw-3_fHmQ8O8K7BcN6oDdRFRZgu5f0z6jVyi-aAEH0tieexRsPNJotenwSJn-eoCytLcIF70LNWhhmFbHNjZffFl5-Tl7blqfG60ztXmeo-N0ISoXXPnEwgV5CxWyTKDagmp0bYeCaiSszUe4YSOGmUeU9xLuM3wBHg93GFWFs3ZSQ_-mnaBnNoLBytd_nS_IOehIDdu1jPmNCJVFNpwOYxrvxisTPa--IjV_zIS5D9WR2dR6h8w8CFkdMlSFssANw`
	const expectedIdObj string = `{"aud":["echo-api"],"exp":1616592091,"iat":1616591491,"iss":"kubernetes.default.svc","kubernetes.io":{"namespace":"authorino","serviceaccount":{"name":"api-consumer","uid":"eb5bcf55-6bdb-4b5b-a7ae-fbb8ad1119cb"}},"nbf":1616591491,"sub":"system:serviceaccount:authorino:api-consumer"}`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth_credentials.NewMockAuthCredentials(ctrl)
	authContextMock := mock_common.NewMockAuthContext(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	authContextMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuth(authCredsMock, tokenReviewData{requestToken, true})
	ret, err := kubernetesAuth.Call(authContextMock, context.TODO())

	assert.NilError(t, err)

	claims, _ := json.Marshal(ret)
	assert.Equal(t, expectedIdObj, string(claims))
}

func TestUnauthenticatedToken(t *testing.T) {
	const requestToken string = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjdXY3BwMVY1cTBPOFF6aFc0U3Ywb1NtaVh4T09qTnpKV2lKN21WVXJObmcifQ.eyJhdWQiOlsiZWNoby1hcGkiXSwiZXhwIjoxNjE2NTkyMDkxLCJpYXQiOjE2MTY1OTE0OTEsImlzcyI6Imt1YmVybmV0ZXMuZGVmYXVsdC5zdmMiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXIiLCJ1aWQiOiJlYjViY2Y1NS02YmRiLTRiNWItYTdhZS1mYmI4YWQxMTE5Y2IifX0sIm5iZiI6MTYxNjU5MTQ5MSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmF1dGhvcmlubzphcGktY29uc3VtZXIifQ.Kp8pkOqFQoriumJTxtpRGJB3F26jpYVpxzXZBLbCSJKYi1CvgwdzsbVwlbbSOl5qCS62xlQCcPAyr3M56jjOjw-3_fHmQ8O8K7BcN6oDdRFRZgu5f0z6jVyi-aAEH0tieexRsPNJotenwSJn-eoCytLcIF70LNWhhmFbHNjZffFl5-Tl7blqfG60ztXmeo-N0ISoXXPnEwgV5CxWyTKDagmp0bYeCaiSszUe4YSOGmUeU9xLuM3wBHg93GFWFs3ZSQ_-mnaBnNoLBytd_nS_IOehIDdu1jPmNCJVFNpwOYxrvxisTPa--IjV_zIS5D9WR2dR6h8w8CFkdMlSFssANw`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth_credentials.NewMockAuthCredentials(ctrl)
	authContextMock := mock_common.NewMockAuthContext(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	authContextMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuth(authCredsMock, tokenReviewData{requestToken, false})
	ret, err := kubernetesAuth.Call(authContextMock, context.TODO())

	assert.Check(t, ret == nil)
	assert.Error(t, err, "Not authenticated")
}

func TestOpaqueToken(t *testing.T) {
	const requestToken string = `some-opaque-token`
	const expectedIdObj string = `{"username":"system:serviceaccount:authorino:api-consumer-sa","uid":"0632367e-2455-44fb-bd01-3cf5b5f4a34b","groups":["system:serviceaccounts","system:serviceaccounts:authorino","system:authenticated"]}`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredsMock := mock_auth_credentials.NewMockAuthCredentials(ctrl)
	authContextMock := mock_common.NewMockAuthContext(ctrl)

	request := &envoy_auth.AttributeContext_HttpRequest{Host: "echo-api"}
	authContextMock.EXPECT().GetHttp().Return(request).AnyTimes()
	authCredsMock.EXPECT().GetCredentialsFromReq(request).Return(requestToken, nil)

	kubernetesAuth := newKubernetesAuth(authCredsMock, tokenReviewData{requestToken, true})
	ret, err := kubernetesAuth.Call(authContextMock, context.TODO())

	assert.NilError(t, err)

	claims, _ := json.Marshal(ret)
	assert.Equal(t, expectedIdObj, string(claims))
}
