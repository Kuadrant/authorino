package identity

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// extractClientCertFromRFC9440 extracts and converts a certificate from RFC 9440 Client-Cert header format to PEM.
// RFC 9440 format: :base64_encoded_DER_cert:
// The certificate is in DER format, base64 encoded, and delimited by colons on either side.
func extractClientCertFromRFC9440(headerValue string) (string, error) {
	// Remove leading and trailing whitespace
	headerValue = strings.TrimSpace(headerValue)

	// RFC 9440: The certificate is delimited by colons
	if !strings.HasPrefix(headerValue, ":") || !strings.HasSuffix(headerValue, ":") {
		return "", fmt.Errorf("invalid Client-Cert header format: missing colon delimiters (expected format: :base64_cert:)")
	}

	// Strip the leading and trailing colons
	base64Cert := strings.TrimPrefix(headerValue, ":")
	base64Cert = strings.TrimSuffix(base64Cert, ":")

	// Remove any whitespace that might have been introduced
	base64Cert = strings.TrimSpace(base64Cert)

	if base64Cert == "" {
		return "", fmt.Errorf("empty certificate in Client-Cert header")
	}

	// Base64 decode the DER certificate
	derCert, err := base64.StdEncoding.DecodeString(base64Cert)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode certificate: %w", err)
	}

	// Convert DER to PEM format
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	}

	pemCert := string(pem.EncodeToMemory(pemBlock))
	if pemCert == "" {
		return "", fmt.Errorf("failed to encode certificate as PEM")
	}

	return pemCert, nil
}
