package auth

import (
	"errors"
	"regexp"
	"strings"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	httputil "github.com/kuadrant/authorino/pkg/http"
)

const (
	defaultCredentialLocationIdentifier = "Bearer"

	credentialNotFoundMsg             = "credential not found"
	credentialNotFoundInHeaderMsg     = "the credential was not found in the request header"
	credentialLocationNotSupportedMsg = "the credential location is not supported"
	authHeaderNotSetMsg               = "the Authorization header is not set"
	cookieHeaderNotSetMsg             = "the Cookie header is not set"
)

var errNotFound = errors.New(credentialNotFoundMsg)

// AuthCredentials combines credential location information with the ability to extract
// credentials from Envoy authorization requests.
type AuthCredentials interface {
	httputil.CredentialLocation
	GetCredentialsFromAuthReq(*envoy_auth.AttributeContext_HttpRequest) (string, error)
}

// NewAuthCredential creates a new instance of AuthCredential
func NewAuthCredential(placement, identifier string) *AuthCredential {
	if placement == "" {
		placement = httputil.InAuthorizationHeader
	}
	if identifier == "" {
		identifier = defaultCredentialLocationIdentifier
	}
	return &AuthCredential{
		Placement:  placement,
		Identifier: identifier,
	}
}

// AuthCredential struct implements the AuthCredentials interface
type AuthCredential struct {
	Placement  string
	Identifier string
}

func (c *AuthCredential) GetPlacement() string {
	return c.Placement
}

func (c *AuthCredential) GetIdentifier() string {
	return c.Identifier
}

// GetCredentialsFromAuthReq will retrieve the secrets from a given location in the Envoy authorization request
func (c *AuthCredential) GetCredentialsFromAuthReq(httpReq *envoy_auth.AttributeContext_HttpRequest) (string, error) {
	switch c.GetPlacement() {
	case httputil.InCustomHeader:
		return getCredFromCustomHeader(httpReq.GetHeaders(), c.GetIdentifier())
	case httputil.InAuthorizationHeader:
		return getCredFromAuthHeader(httpReq.GetHeaders(), c.GetIdentifier())
	case httputil.InCookie:
		return getFromCookieHeader(httpReq.GetHeaders(), c.GetIdentifier())
	case httputil.InQuery:
		return getCredFromQuery(httpReq.GetPath(), c.GetIdentifier())
	default:
		return "", errors.New(credentialLocationNotSupportedMsg)
	}
}

func getCredFromCustomHeader(headers map[string]string, keyName string) (string, error) {
	cred, ok := headers[strings.ToLower(keyName)]
	if !ok {
		return "", errNotFound
	}
	return cred, nil
}

func getCredFromAuthHeader(headers map[string]string, keyName string) (string, error) {
	authHeader, ok := headers["authorization"]

	if !ok {
		return "", errNotFound
	}
	prefix := keyName + " "
	if strings.HasPrefix(authHeader, prefix) {
		return strings.TrimPrefix(authHeader, prefix), nil
	}
	return "", errNotFound
}

func getFromCookieHeader(headers map[string]string, keyName string) (string, error) {
	header, ok := headers["cookie"]
	if !ok {
		return "", errNotFound
	}

	for _, part := range strings.Split(header, ";") {
		keyAndValue := strings.TrimSpace(part)
		if strings.HasPrefix(keyAndValue, keyName+"=") {
			return strings.TrimPrefix(keyAndValue, keyName+"="), nil
		}
	}

	return "", errNotFound
}

func getCredFromQuery(path string, keyName string) (string, error) {
	const credValue = "credValue"
	regex := regexp.MustCompile("([?&]" + keyName + "=)(?P<" + credValue + ">[^&]*)")
	matches := regex.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", errNotFound
	}
	return matches[regex.SubexpIndex(credValue)], nil
}
