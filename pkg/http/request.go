package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxURLLength = 2048 // Standard reasonable limit for URLs

// Credential location constants define where credentials can be placed.
// These form a closed set - use these constants rather than raw strings.
const (
	InCustomHeader        = "custom_header"
	InAuthorizationHeader = "authorization_header"
	InCookie              = "cookie"
	InQuery               = "query"
)

// CredentialLocation describes where credentials are located and how they are identified.
// This interface is used for injecting credentials into outbound HTTP requests.
type CredentialLocation interface {
	// GetPlacement returns where the credential should be placed.
	// Use the In* constants (InAuthorizationHeader, InCustomHeader, InCookie, InQuery).
	GetPlacement() string

	// GetIdentifier returns the identifier for the credential that matches the placement
	// (e.g., "Bearer", "X-API-Key", "session_id", "access_token")
	GetIdentifier() string
}

// NewRequest wraps http.NewRequestWithContext with URL validation.
// It ensures the URL is well-formed, uses HTTP/HTTPS scheme, and doesn't contain
// control characters or other suspicious patterns that could indicate SSRF attempts.
func NewRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	if err := ValidateURL(rawURL); err != nil {
		return nil, err
	}
	return http.NewRequestWithContext(ctx, method, rawURL, body)
}

// NewRequestWithCredentials creates an HTTP request with credentials injected based on the
// CredentialLocation configuration. It supports credentials in authorization headers,
// custom headers, cookies, and query parameters.
//
// The URL is validated before the request is created to prevent SSRF attacks.
func NewRequestWithCredentials(ctx context.Context, method, rawURL string, body io.Reader, credentialInjector CredentialLocation, credentialValue string) (*http.Request, error) {
	if credentialInjector == nil {
		return nil, fmt.Errorf("credentialInjector cannot be nil")
	}

	finalURL := rawURL

	// Add credentials to query string if needed
	if credentialInjector.GetPlacement() == InQuery && credentialValue != "" {
		separator := "&"
		if !strings.Contains(finalURL, "?") {
			separator = "?"
		}
		finalURL = finalURL + separator + credentialInjector.GetIdentifier() + "=" + credentialValue
	}

	// Create the request with validation
	req, err := NewRequest(ctx, method, finalURL, body)
	if err != nil {
		return nil, err
	}

	// Don't add credentials if the value is empty
	if credentialValue == "" {
		return req, nil
	}

	// Add credentials based on location
	switch credentialInjector.GetPlacement() {
	case InAuthorizationHeader:
		req.Header.Set("Authorization", credentialInjector.GetIdentifier()+" "+credentialValue)
	case InCustomHeader:
		req.Header.Set(credentialInjector.GetIdentifier(), credentialValue)
	case InCookie:
		req.Header.Set("Cookie", credentialInjector.GetIdentifier()+"="+credentialValue)
	case InQuery:
		// Already handled above when building the URL
	default:
		return nil, fmt.Errorf("unsupported credentials location: %s", credentialInjector.GetPlacement())
	}

	return req, nil
}

// ValidateURL ensures a URL string is well-formed and safe to use for outbound HTTP requests.
// It performs the following checks:
//   - URL length is within reasonable limits (2048 characters)
//   - URL parses correctly
//   - Scheme is http or https only
//   - Host is not empty
//   - URL does not contain control characters (except space in query/fragment)
//   - URL does not contain null bytes
//
// This helps prevent Server-Side Request Forgery (SSRF) attacks when URLs are
// constructed from user-controlled values (e.g., JWT claims, headers, query parameters).
//
// Note: This validation does NOT block private IP addresses or internal hostnames,
// as those may be legitimate targets for metadata or internal service calls.
func ValidateURL(rawURL string) error {
	// Check URL length to prevent extremely long URLs
	if len(rawURL) > maxURLLength {
		return fmt.Errorf("invalid URL: exceeds maximum length of %d characters", maxURLLength)
	}

	// Check for null bytes
	if strings.Contains(rawURL, "\x00") {
		return fmt.Errorf("invalid URL: contains null byte")
	}

	// Check for control characters (ASCII < 32), excluding space (32)
	// Allow control chars only in the query string and fragment (after '?' or '#')
	schemeAndAuthority := rawURL
	if idx := strings.IndexAny(rawURL, "?#"); idx != -1 {
		schemeAndAuthority = rawURL[:idx]
	}
	for _, char := range schemeAndAuthority {
		if char < 32 {
			return fmt.Errorf("invalid URL: contains control character")
		}
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Ensure the URL has a scheme
	if parsedURL.Scheme == "" {
		return fmt.Errorf("invalid URL: missing scheme (expected http or https)")
	}

	// Only allow HTTP and HTTPS schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid URL: unsupported scheme %q (only http and https are allowed)", parsedURL.Scheme)
	}

	// Ensure the URL has a host
	if parsedURL.Host == "" {
		return fmt.Errorf("invalid URL: missing host")
	}

	return nil
}

// NewClient creates an HTTP client for making requests.
// Currently returns http.DefaultClient, but will support configurable timeouts in the future (issue #620).
func NewClient() *http.Client {
	return http.DefaultClient
}
