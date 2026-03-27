package identity

import (
	"encoding/base64"
	"encoding/pem"
	"testing"

	"gotest.tools/assert"
)

func TestExtractClientCertFromRFC9440(t *testing.T) {
	// Use a real certificate from the test fixtures
	if len(testCerts) == 0 || testCerts["john"] == nil {
		t.Skip("Test certificates not initialized")
	}

	// Get the PEM certificate and decode to DER
	block, _ := pem.Decode(testCerts["john"]["tls.crt"])
	if block == nil {
		t.Fatal("Failed to decode test PEM certificate")
	}
	derCert := block.Bytes

	tests := []struct {
		name        string
		headerValue string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid RFC 9440 format",
			headerValue: ":" + base64.StdEncoding.EncodeToString(derCert) + ":",
			wantErr:     false,
		},
		{
			name:        "valid with whitespace around",
			headerValue: "  :" + base64.StdEncoding.EncodeToString(derCert) + ":  ",
			wantErr:     false,
		},
		{
			name:        "missing leading colon",
			headerValue: base64.StdEncoding.EncodeToString(derCert) + ":",
			wantErr:     true,
			errContains: "missing colon delimiters",
		},
		{
			name:        "missing trailing colon",
			headerValue: ":" + base64.StdEncoding.EncodeToString(derCert),
			wantErr:     true,
			errContains: "missing colon delimiters",
		},
		{
			name:        "missing both colons",
			headerValue: base64.StdEncoding.EncodeToString(derCert),
			wantErr:     true,
			errContains: "missing colon delimiters",
		},
		{
			name:        "empty certificate",
			headerValue: "::",
			wantErr:     true,
			errContains: "empty certificate",
		},
		{
			name:        "invalid base64",
			headerValue: ":not-valid-base64!@#$:",
			wantErr:     true,
			errContains: "failed to base64 decode",
		},
		{
			name:        "empty string",
			headerValue: "",
			wantErr:     true,
			errContains: "missing colon delimiters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractClientCertFromRFC9440(tt.headerValue)

			if tt.wantErr {
				assert.Check(t, err != nil)
				if tt.errContains != "" {
					assert.ErrorContains(t, err, tt.errContains)
				}
				assert.Equal(t, result, "")
			} else {
				assert.NilError(t, err)
				assert.Check(t, result != "")
				// Verify result is valid PEM
				block, _ := pem.Decode([]byte(result))
				assert.Check(t, block != nil)
				assert.Equal(t, block.Type, "CERTIFICATE")
			}
		})
	}
}

func TestExtractClientCertFromRFC9440WithRealCert(t *testing.T) {
	// Use a real certificate from the test fixtures
	if len(testCerts) == 0 || testCerts["john"] == nil {
		t.Skip("Test certificates not initialized")
	}

	// Get the PEM certificate
	pemCert := testCerts["john"]["tls.crt"]

	// Decode PEM to DER
	block, _ := pem.Decode(pemCert)
	if block == nil {
		t.Fatal("Failed to decode test certificate")
	}
	derCert := block.Bytes

	// Encode to RFC 9440 format
	rfc9440Value := ":" + base64.StdEncoding.EncodeToString(derCert) + ":"

	// Extract using our function
	result, err := extractClientCertFromRFC9440(rfc9440Value)
	assert.NilError(t, err)

	// Verify the result is valid PEM
	resultBlock, _ := pem.Decode([]byte(result))
	assert.Check(t, resultBlock != nil)
	assert.Equal(t, resultBlock.Type, "CERTIFICATE")

	// Verify the DER bytes match
	assert.DeepEqual(t, resultBlock.Bytes, derCert)
}
