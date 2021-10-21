package auth_credentials

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/kuadrant/authorino/pkg/common/log"

	envoyServiceAuthV3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// AuthCredentials interface represents the methods needed to fetch credentials from input
type AuthCredentials interface {
	GetCredentialsFromReq(*envoyServiceAuthV3.AttributeContext_HttpRequest) (string, error)
	GetCredentialsKeySelector() string
	GetCredentialsIn() string
	BuildRequestWithCredentials(ctx context.Context, endpoint string, method string, credentialValue string, body io.Reader) (*http.Request, error)
}

// AuthCredential struct implements the AuthCredentials interface
type AuthCredential struct {
	KeySelector string `yaml:"keySelector"`
	In          string `yaml:"in"`
}

const (
	inCustomHeader = "custom_header"
	inAuthHeader   = "authorization_header"
	inCookieHeader = "cookie"
	inQuery        = "query"

	defaultKeySelector = "Bearer"

	credentialNotFoundMsg             = "credential not found"
	credentialNotFoundInHeaderMsg     = "the credential was not found in the request header"
	credentialLocationNotSupportedMsg = "the credential location is not supported"
	authHeaderNotSetMsg               = "the Authorization header is not set"
	cookieHeaderNotSetMsg             = "the Cookie header is not set"
)

var (
	logger = log.WithName("authcredential").V(1)

	notFoundErr = fmt.Errorf(credentialNotFoundMsg)
)

// NewAuthCredential creates a new instance of AuthCredential
func NewAuthCredential(selector string, location string) *AuthCredential {
	var keySelector, in string
	if keySelector = selector; keySelector == "" {
		keySelector = defaultKeySelector
	}
	if in = location; in == "" {
		in = inAuthHeader
	}

	return &AuthCredential{
		keySelector,
		in,
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

func (c *AuthCredential) GetCredentialsKeySelector() string {
	return c.KeySelector
}

func (c *AuthCredential) GetCredentialsIn() string {
	return c.In
}

func (c *AuthCredential) BuildRequestWithCredentials(ctx context.Context, endpoint string, method string, credentialValue string, body io.Reader) (*http.Request, error) {
	url := endpoint

	// build url with creds (if credentialValue is not empty)
	if c.In == inQuery && credentialValue != "" {
		var separator string
		if strings.Contains(url, "?") {
			separator = "&"
		} else {
			separator = "?"
		}
		url = url + separator + c.KeySelector + "=" + credentialValue
	}

	// build request
	if req, err := http.NewRequestWithContext(ctx, method, url, body); err != nil {
		return nil, err
	} else {
		// don't add creds if credentialValue is empty
		if credentialValue == "" {
			return req, nil
		}

		// add creds to request
		switch c.In {
		case inAuthHeader:
			req.Header.Set("Authorization", c.KeySelector+" "+credentialValue)
		case inCustomHeader:
			req.Header.Set(c.KeySelector, credentialValue)
		case inCookieHeader:
			req.Header.Set("Cookie", c.KeySelector+"="+credentialValue)
		case inQuery:
			// already done
		default:
			return nil, fmt.Errorf("unsupported credentials location")
		}
		return req, nil
	}
}

func getCredFromCustomHeader(headers map[string]string, keyName string) (string, error) {
	cred, ok := headers[strings.ToLower(keyName)]
	if !ok {
		logger.Error(notFoundErr, credentialNotFoundInHeaderMsg)
		return "", notFoundErr
	}
	return cred, nil
}

func getCredFromAuthHeader(headers map[string]string, keyName string) (string, error) {
	authHeader, ok := headers["authorization"]

	if !ok {
		logger.Error(notFoundErr, authHeaderNotSetMsg)
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
		logger.Error(notFoundErr, cookieHeaderNotSetMsg)
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
