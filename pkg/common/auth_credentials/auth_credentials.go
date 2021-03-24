package auth_credentials

import (
	"fmt"
	"regexp"
	"strings"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ctrl "sigs.k8s.io/controller-runtime"
)

// AuthCredentials interface represents the methods needed to fetch credentials from input
type AuthCredentials interface {
	GetCredentialsFromReq(*envoyServiceAuthV3.AttributeContext_HttpRequest) (string, error)
}

// AuthCredential struct implements the AuthCredentials interface
type AuthCredential struct {
	KeySelector string `yaml:"key_selector"`
	In          string `yaml:"in"`
}

const (
	inCustomHeader = "custom_header"
	inAuthHeader   = "authorization_header"
	inCookieHeader = "cookie"
	inQuery        = "query"

	credentialNotFoundMsg             = "credential not found"
	credentialNotFoundInHeaderMsg     = "the credential was not found in the request header"
	credentialLocationNotSupportedMsg = "the credential location is not supported"
	authHeaderNotSetMsg               = "the Authorization header is not set"
	cookieHeaderNotSetMsg             = "the Cookie header is not set"
)

var (
	authCredLog = ctrl.Log.WithName("Authorino").WithName("AuthCredential")
	notFoundErr = fmt.Errorf(credentialNotFoundMsg)
)

// NewAuthCredential creates a new instance of AuthCredential
func NewAuthCredential(selector string, location string) *AuthCredential {
	return &AuthCredential{
		selector,
		location,
	}
}

// GetCredentialsFromReq will retrieve the secrets from a given location
func (c *AuthCredential) GetCredentialsFromReq(httpReq *envoyServiceAuthV3.AttributeContext_HttpRequest) (string, error) {
	switch c.In {
	case inCustomHeader:
		return getCredFromCustomHeader(httpReq.GetHeaders(), c.KeySelector)
	case inAuthHeader:
		return getCredFromAuthHeader(httpReq.GetHeaders(), c.KeySelector)
	case inCookieHeader:
		return getFromCookieHeader(httpReq.GetHeaders(), c.KeySelector)
	case inQuery:
		return getCredFromQuery(httpReq.GetPath(), c.KeySelector)
	default:
		return "", fmt.Errorf(credentialLocationNotSupportedMsg)
	}
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

func getFromCookieHeader(headers map[string]string, keyName string) (string, error) {
	header, ok := headers["cookie"]
	if !ok {
		authCredLog.Error(notFoundErr, cookieHeaderNotSetMsg)
		return "", notFoundErr
	}

	for _, part := range strings.Split(header, ";") {
		keyAndValue := strings.Split(strings.TrimSpace(part), "=")
		if keyAndValue[0] == keyName {
			return keyAndValue[1], nil
		}
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
