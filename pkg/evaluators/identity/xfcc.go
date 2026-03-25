package identity

import (
	"fmt"
	"net/url"
	"strings"
)

// XFCC header field names according to Envoy spec
// https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
const (
	xfccHeaderName = "x-forwarded-client-cert"
	xfccFieldBy    = "by"
	xfccFieldHash  = "hash"
	xfccFieldCert  = "cert"
	xfccFieldChain = "chain"
	xfccFieldSubj  = "subject"
	xfccFieldURI   = "uri"
	xfccFieldDNS   = "dns"
)

// xfccElement represents a single element in the XFCC header
// Each element corresponds to one certificate in the chain
type xfccElement struct {
	By      string
	Hash    string
	Cert    string // URL-encoded PEM certificate
	Chain   string // URL-encoded PEM certificate chain
	Subject string
	URI     string
	DNS     string
}

// parseXFCCHeader parses the X-Forwarded-Client-Cert header value
// Returns a slice of xfccElement, one per certificate element
func parseXFCCHeader(headerValue string) ([]xfccElement, error) {
	if headerValue == "" {
		return nil, fmt.Errorf("XFCC header is empty")
	}

	// XFCC header elements are comma-separated
	// Each element has semicolon-delimited key=value pairs
	var elements []xfccElement

	// Split by comma to get individual certificate elements
	parts := splitXFCCElements(headerValue)

	for _, part := range parts {
		element, err := parseXFCCElement(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("failed to parse XFCC element: %w", err)
		}
		elements = append(elements, element)
	}

	return elements, nil
}

// splitXFCCElements splits the XFCC header by commas, respecting quoted values
func splitXFCCElements(header string) []string {
	var elements []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(header); i++ {
		char := header[i]

		switch char {
		case '"':
			inQuotes = !inQuotes
			current.WriteByte(char)
		case ',':
			if inQuotes {
				current.WriteByte(char)
			} else {
				if current.Len() > 0 {
					elements = append(elements, current.String())
					current.Reset()
				}
			}
		default:
			current.WriteByte(char)
		}
	}

	// Add the last element
	if current.Len() > 0 {
		elements = append(elements, current.String())
	}

	return elements
}

// parseXFCCElement parses a single XFCC element (one certificate)
func parseXFCCElement(elementStr string) (xfccElement, error) {
	element := xfccElement{}

	// Split by semicolon to get key=value pairs
	pairs := strings.Split(elementStr, ";")

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// Split key=value
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes from value if present
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		// Assign to appropriate field
		switch strings.ToLower(key) {
		case xfccFieldBy:
			element.By = value
		case xfccFieldHash:
			element.Hash = value
		case xfccFieldCert:
			element.Cert = value
		case xfccFieldChain:
			element.Chain = value
		case xfccFieldSubj:
			element.Subject = value
		case xfccFieldURI:
			element.URI = value
		case xfccFieldDNS:
			element.DNS = value
		}
	}

	return element, nil
}

// extractClientCertFromXFCC extracts the client certificate from XFCC header
// Returns the PEM-encoded certificate string (URL-decoded)
// Per design decision: uses Cert field (not Chain), validates only leaf certificate
// If multiple certificates present, uses the first one
func extractClientCertFromXFCC(headerValue string) (string, error) {
	elements, err := parseXFCCHeader(headerValue)
	if err != nil {
		return "", err
	}

	// Per design decision: if multiple certificates present, use the first one
	if len(elements) == 0 {
		return "", fmt.Errorf("no XFCC elements found")
	}

	// Per design decision: prefer Cert field over Chain field
	certValue := elements[0].Cert
	if certValue == "" {
		// Fallback to Chain if Cert is not present
		certValue = elements[0].Chain
	}

	if certValue == "" {
		return "", fmt.Errorf("client certificate not found in XFCC header")
	}

	// URL-decode the certificate
	pemCert, err := url.QueryUnescape(certValue)
	if err != nil {
		return "", fmt.Errorf("failed to URL-decode certificate from XFCC header: %w", err)
	}

	return pemCert, nil
}

// getXFCCHeaderFromRequest extracts the XFCC header value from request headers
func getXFCCHeaderFromRequest(headers map[string]string, headerName string) (string, error) {
	if headerName == "" {
		headerName = xfccHeaderName
	}

	// HTTP headers are case-insensitive, normalize to lowercase
	headerValue, ok := headers[strings.ToLower(headerName)]
	if !ok {
		return "", fmt.Errorf("header %s not found in request", headerName)
	}

	return headerValue, nil
}
