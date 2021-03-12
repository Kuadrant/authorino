package auth_credentials

import (
	"context"
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"gotest.tools/assert"
)

func TestConstants(t *testing.T) {
	assert.Check(t, "custom_header" == inCustomHeader)
	assert.Check(t, "authorization_header" == inAuthHeader)
	assert.Check(t, "query" == inQuery)
	assert.Check(t, "credential not found" == credentialNotFoundMsg)
	assert.Check(t, "the credential was not found in the request header" == credentialNotFoundInHeaderMsg)
	assert.Check(t, "the credential location is not supported" == credentialLocationNotSupported)
	assert.Check(t, "the Authorization header is not set" == authHeaderNotSetMsg)
}

func TestNewAuthCredential(t *testing.T) {
	creds := NewAuthCredential("api_key", "query", nil)
	assert.Check(t, creds.KeySelector == "api_key")
	assert.Check(t, creds.In == "query")
}

func TestGetCredentialsLocationNotSupported(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{}

	authCredentials := AuthCredential{
		In: "body",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "the credential location is not supported")
}

func TestGetCredentialsFromCustomHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"x-api-key": "DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		KeySelector: "X-API-KEY",
		In:          "custom_header",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromCustomHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{}

	authCredentials := AuthCredential{
		KeySelector: "X-API-KEY",
		In:          "custom_header",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestGetCredentialsFromAuthHeaderSuccess(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"authorization": "X-API-KEY DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		KeySelector: "X-API-KEY",
		In:          "authorization_header",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromAuthHeaderFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Headers: map[string]string{"authorization": "X-API-KEY DasUberApiKey"},
	}

	authCredentials := AuthCredential{
		KeySelector: "Bearer",
		In:          "authorization_header",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

func TestGetCredentialsFromQuerySuccess(t *testing.T) {
	// as first query param
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?api_key=DasUberApiKey",
	}

	authCredentials := AuthCredential{
		KeySelector: "api_key",
		In:          "query",
	}
	cred, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")

	// as a nth query param
	httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?third_impact=true&api_key=DasUberApiKey&some=scheisse",
	}

	cred, err = authCredentials.GetCredentialsFromReq(&httpReq)

	assert.NilError(t, err)
	assert.Check(t, cred == "DasUberApiKey")
}

func TestGetCredentialsFromQueryFail(t *testing.T) {
	var httpReq = envoyServiceAuthV3.AttributeContext_HttpRequest{
		Path: "/seele.de/hip?third_impact=true&some=scheisse",
	}

	authCredentials := AuthCredential{
		KeySelector: "api_key",
		In:          "query",
	}
	_, err := authCredentials.GetCredentialsFromReq(&httpReq)

	assert.Error(t, err, "credential not found")
}

type MockK8sClient struct{}

var (
	listSecretsFunc func(*v1.SecretList) error
)

func (k *MockK8sClient) Get(ctx context.Context, key client.ObjectKey, obj runtime.Object) error {
	return nil
}

func (k *MockK8sClient) List(ctx context.Context, list runtime.Object, opts ...client.ListOption) error {
	return listSecretsFunc(list.(*v1.SecretList))
}

var mockK8sClient MockK8sClient

func TestGetCredentialsFromClusterSuccess(t *testing.T) {
	listSecretsFunc = func(list *v1.SecretList) error {
		var secrets []v1.Secret
		secrets = append(
			secrets,
			v1.Secret{Data: map[string][]byte{"X-API-KEY": []byte("DasUberApiKey")}},
			v1.Secret{Data: map[string][]byte{"X-API-KEY": []byte("DasUberApiKey2")}},
		)
		list.Items = append(list.Items, secrets...)
		return nil
	}
	authCred := NewAuthCredential("X-API-KEY", "custom_header", &mockK8sClient)
	creds, err := authCred.GetCredentialsFromCluster(context.TODO(), map[string]string{})

	assert.NilError(t, err)
	assert.Check(t, len(creds) == 2)
	assert.Check(t, creds[0] == "DasUberApiKey")
	assert.Check(t, creds[1] == "DasUberApiKey2")
}

func TestGetCredentialsFromClusterFail(t *testing.T) {
	listSecretsFunc = func(list *v1.SecretList) error {
		return fmt.Errorf("something terribly wrong happened")
	}
	authCred := NewAuthCredential("X-API-KEY", "custom_header", &mockK8sClient)
	_, err := authCred.GetCredentialsFromCluster(context.TODO(), map[string]string{})

	assert.Error(t, err, "something terribly wrong happened")
}
