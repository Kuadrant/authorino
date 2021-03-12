package auth_credentials

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	v1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type AuthCredentials interface {
	GetCredentialsFromReq(*envoyServiceAuthV3.AttributeContext_HttpRequest) (string, error)
	GetCredentialsFromCluster(context.Context, map[string]string) ([]string, error)
}

type AuthCredential struct {
	KeySelector string `yaml:"key_selector"`
	In          string `yaml:"in"`
	k8sClient   client.Reader
}

const (
	inCustomHeader = "custom_header"
	inAuthHeader   = "authorization_header"
	inQuery        = "query"

	credentialNotFoundMsg          = "credential not found"
	credentialNotFoundInHeaderMsg  = "the credential was not found in the request header"
	credentialLocationNotSupported = "the credential location is not supported"
	authHeaderNotSetMsg            = "the Authorization header is not set"
)

var (
	authCredLog = ctrl.Log.WithName("Authorino").WithName("AuthCredential")
	notFoundErr = fmt.Errorf(credentialNotFoundMsg)
)

func NewAuthCredential(selector string, location string, k8sClient client.Reader) *AuthCredential {
	return &AuthCredential{
		selector,
		location,
		k8sClient,
	}
}

func (c *AuthCredential) GetCredentialsFromReq(httpReq *envoyServiceAuthV3.AttributeContext_HttpRequest) (string, error) {
	switch c.In {
	case inCustomHeader:
		return getCredFromCustomHeader(httpReq.GetHeaders(), c.KeySelector)
	case inAuthHeader:
		return getCredFromAuthHeader(httpReq.GetHeaders(), c.KeySelector)
	case inQuery:
		return getCredFromQuery(httpReq.GetPath(), c.KeySelector)
	default:
		return "", fmt.Errorf(credentialLocationNotSupported)
	}
}

func (c *AuthCredential) GetCredentialsFromCluster(ctx context.Context, labelSelectors map[string]string) ([]string, error) {
	var matchingLabels client.MatchingLabels = labelSelectors
	var secretList = &v1.SecretList{}
	if err := c.k8sClient.List(ctx, secretList, matchingLabels); err != nil {
		return nil, err
	}
	var parsedSecrets []string

	for _, secret := range secretList.Items {
		parsedSecrets = append(parsedSecrets, string(secret.Data[c.KeySelector]))
	}

	return parsedSecrets, nil
}

func getCredFromCustomHeader(headers map[string]string, keyName string) (string, error) {
	cred, ok := headers[strings.ToLower(keyName)]
	if !ok {
		authCredLog.Error(notFoundErr, credentialNotFoundInHeaderMsg)
		return "", notFoundErr
	}
	return cred, nil
}
func getCredFromAuthHeader(headers map[string]string, keyName string) (string, error) {
	authHeader, ok := headers["authorization"]

	if !ok {
		authCredLog.Error(notFoundErr, authHeaderNotSetMsg)
		return "", notFoundErr
	}
	prefix := keyName + " "
	if strings.HasPrefix(authHeader, prefix) {
		return strings.TrimPrefix(authHeader, prefix), nil
	}
	return "", notFoundErr
}

func getCredFromQuery(path string, keyName string) (string, error) {
	const credValue = "credValue"
	regex := regexp.MustCompile("([?&]" + keyName + "=)(?P<" + credValue + ">[^&]*)")
	matches := regex.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", notFoundErr
	}
	return matches[regex.SubexpIndex(credValue)], nil
}
