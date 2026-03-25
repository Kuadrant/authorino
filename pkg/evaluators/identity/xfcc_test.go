package identity

import (
	"net/url"
	"testing"

	"gotest.tools/assert"
)

func TestParseXFCCHeader(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantLen     int
		wantErr     bool
		checkFirst  func(*testing.T, xfccElement)
	}{
		{
			name:        "single certificate",
			headerValue: `Hash=abc123;Cert="-----BEGIN%20CERTIFICATE-----%0Acert-data%0A-----END%20CERTIFICATE-----%0A";Subject="CN=example.com,O=Example"`,
			wantLen:     1,
			wantErr:     false,
			checkFirst: func(t *testing.T, elem xfccElement) {
				assert.Equal(t, elem.Hash, "abc123")
				assert.Equal(t, elem.Cert, "-----BEGIN%20CERTIFICATE-----%0Acert-data%0A-----END%20CERTIFICATE-----%0A")
				assert.Equal(t, elem.Subject, "CN=example.com,O=Example")
			},
		},
		{
			name:        "multiple fields",
			headerValue: `By=spiffe://cluster.local/ns/default/sa/frontend;Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Subject="/C=US/ST=CA/L=San Francisco/O=Example/CN=test.example.com";URI=spiffe://cluster.local/ns/default/sa/default;DNS=test.example.com;Cert="-----BEGIN%20CERTIFICATE-----%0Acert-data%0A-----END%20CERTIFICATE-----%0A"`,
			wantLen:     1,
			wantErr:     false,
			checkFirst: func(t *testing.T, elem xfccElement) {
				assert.Equal(t, elem.By, "spiffe://cluster.local/ns/default/sa/frontend")
				assert.Equal(t, elem.Hash, "468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688")
				assert.Equal(t, elem.Subject, "/C=US/ST=CA/L=San Francisco/O=Example/CN=test.example.com")
				assert.Equal(t, elem.URI, "spiffe://cluster.local/ns/default/sa/default")
				assert.Equal(t, elem.DNS, "test.example.com")
				assert.Equal(t, elem.Cert, "-----BEGIN%20CERTIFICATE-----%0Acert-data%0A-----END%20CERTIFICATE-----%0A")
			},
		},
		{
			name:        "multiple certificates (comma-separated)",
			headerValue: `Hash=abc1;Cert="cert1",Hash=abc2;Cert="cert2"`,
			wantLen:     2,
			wantErr:     false,
			checkFirst: func(t *testing.T, elem xfccElement) {
				assert.Equal(t, elem.Hash, "abc1")
				assert.Equal(t, elem.Cert, "cert1")
			},
		},
		{
			name:        "empty header",
			headerValue: "",
			wantLen:     0,
			wantErr:     true,
		},
		{
			name:        "cert field with chain",
			headerValue: `Hash=abc;Cert="cert1";Chain="chain1"`,
			wantLen:     1,
			wantErr:     false,
			checkFirst: func(t *testing.T, elem xfccElement) {
				assert.Equal(t, elem.Cert, "cert1")
				assert.Equal(t, elem.Chain, "chain1")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elements, err := parseXFCCHeader(tt.headerValue)
			if tt.wantErr {
				assert.Check(t, err != nil)
			} else {
				assert.NilError(t, err)
				assert.Equal(t, len(elements), tt.wantLen)
				if tt.checkFirst != nil && len(elements) > 0 {
					tt.checkFirst(t, elements[0])
				}
			}
		})
	}
}

func TestExtractClientCertFromXFCC(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8YN5H7iNjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDDAJ0
-----END CERTIFICATE-----
`
	urlEncodedCert := url.QueryEscape(pemCert)

	tests := []struct {
		name        string
		headerValue string
		wantCert    string
		wantErr     bool
	}{
		{
			name:        "valid cert in Cert field",
			headerValue: `Hash=abc;Cert="` + urlEncodedCert + `"`,
			wantCert:    pemCert,
			wantErr:     false,
		},
		{
			name:        "valid cert in Chain field (fallback)",
			headerValue: `Hash=abc;Chain="` + urlEncodedCert + `"`,
			wantCert:    pemCert,
			wantErr:     false,
		},
		{
			name:        "Cert preferred over Chain",
			headerValue: `Hash=abc;Cert="` + urlEncodedCert + `";Chain="other-cert"`,
			wantCert:    pemCert,
			wantErr:     false,
		},
		{
			name:        "no cert field",
			headerValue: `Hash=abc;Subject="CN=test"`,
			wantCert:    "",
			wantErr:     true,
		},
		{
			name:        "empty header",
			headerValue: "",
			wantCert:    "",
			wantErr:     true,
		},
		{
			name:        "invalid URL encoding",
			headerValue: `Hash=abc;Cert="%ZZ%invalid"`,
			wantCert:    "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := extractClientCertFromXFCC(tt.headerValue)
			if tt.wantErr {
				assert.Check(t, err != nil)
			} else {
				assert.NilError(t, err)
				assert.Equal(t, cert, tt.wantCert)
			}
		})
	}
}

func TestGetXFCCHeaderFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		headerName string
		wantValue  string
		wantErr    bool
	}{
		{
			name: "default header name",
			headers: map[string]string{
				"x-forwarded-client-cert": "Hash=abc;Cert=xyz",
			},
			headerName: "",
			wantValue:  "Hash=abc;Cert=xyz",
			wantErr:    false,
		},
		{
			name: "custom header name",
			headers: map[string]string{
				"x-custom-cert": "Hash=abc;Cert=xyz",
			},
			headerName: "x-custom-cert",
			wantValue:  "Hash=abc;Cert=xyz",
			wantErr:    false,
		},
		{
			name: "case insensitive",
			headers: map[string]string{
				"x-forwarded-client-cert": "Hash=abc;Cert=xyz",
			},
			headerName: "X-Forwarded-Client-Cert",
			wantValue:  "Hash=abc;Cert=xyz",
			wantErr:    false,
		},
		{
			name: "header not found",
			headers: map[string]string{
				"other-header": "value",
			},
			headerName: "",
			wantValue:  "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := getXFCCHeaderFromRequest(tt.headers, tt.headerName)
			if tt.wantErr {
				assert.Check(t, err != nil)
			} else {
				assert.NilError(t, err)
				assert.Equal(t, value, tt.wantValue)
			}
		})
	}
}

func TestSplitXFCCElements(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "single element",
			header: `Hash=abc;Cert="xyz"`,
			want:   []string{`Hash=abc;Cert="xyz"`},
		},
		{
			name:   "multiple elements",
			header: `Hash=abc;Cert="xyz",Hash=def;Cert="uvw"`,
			want:   []string{`Hash=abc;Cert="xyz"`, `Hash=def;Cert="uvw"`},
		},
		{
			name:   "comma in quoted value",
			header: `Hash=abc;Cert="xyz,123",Hash=def;Cert="uvw"`,
			want:   []string{`Hash=abc;Cert="xyz,123"`, `Hash=def;Cert="uvw"`},
		},
		{
			name:   "empty",
			header: "",
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitXFCCElements(tt.header)
			assert.Equal(t, len(got), len(tt.want))
			for i := range got {
				assert.Equal(t, got[i], tt.want[i])
			}
		})
	}
}

func TestSplitKeyValue(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		wantKey   string
		wantValue string
		wantOk    bool
	}{
		{
			name:      "simple key value",
			s:         "Hash=abc",
			wantKey:   "Hash",
			wantValue: "abc",
			wantOk:    true,
		},
		{
			name:      "equals in quoted value",
			s:         `Cert="data=with=equals"`,
			wantKey:   "Cert",
			wantValue: `"data=with=equals"`,
			wantOk:    true,
		},
		{
			name:      "multiple equals in quoted value",
			s:         `Subject="CN=test,OU=dev,O=company"`,
			wantKey:   "Subject",
			wantValue: `"CN=test,OU=dev,O=company"`,
			wantOk:    true,
		},
		{
			name:      "unquoted value with equals",
			s:         "Subject=CN=test",
			wantKey:   "Subject",
			wantValue: "CN=test",
			wantOk:    true,
		},
		{
			name:      "no equals sign",
			s:         "NoEqualsHere",
			wantKey:   "",
			wantValue: "",
			wantOk:    false,
		},
		{
			name:      "empty string",
			s:         "",
			wantKey:   "",
			wantValue: "",
			wantOk:    false,
		},
		{
			name:      "only equals",
			s:         "=",
			wantKey:   "",
			wantValue: "",
			wantOk:    true,
		},
		{
			name:      "equals at start",
			s:         "=value",
			wantKey:   "",
			wantValue: "value",
			wantOk:    true,
		},
		{
			name:      "equals at end",
			s:         "key=",
			wantKey:   "key",
			wantValue: "",
			wantOk:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, value, ok := splitKeyValue(tt.s)
			assert.Equal(t, ok, tt.wantOk)
			if tt.wantOk {
				assert.Equal(t, key, tt.wantKey)
				assert.Equal(t, value, tt.wantValue)
			}
		})
	}
}

func TestSplitXFCCPairs(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want []string
	}{
		{
			name: "simple pairs",
			s:    `Hash=abc;Cert=xyz`,
			want: []string{"Hash=abc", "Cert=xyz"},
		},
		{
			name: "semicolon in quoted value",
			s:    `Hash=abc;Cert="xyz;123";Subject="CN=test"`,
			want: []string{"Hash=abc", `Cert="xyz;123"`, `Subject="CN=test"`},
		},
		{
			name: "multiple semicolons in quoted value",
			s:    `Hash=abc;Cert="a;b;c;d";Subject="test"`,
			want: []string{"Hash=abc", `Cert="a;b;c;d"`, `Subject="test"`},
		},
		{
			name: "no quotes",
			s:    `Hash=abc;Subject=CN=test`,
			want: []string{"Hash=abc", "Subject=CN=test"},
		},
		{
			name: "mixed quoted and unquoted",
			s:    `Hash=abc;Cert="xyz";URI=spiffe://test`,
			want: []string{"Hash=abc", `Cert="xyz"`, "URI=spiffe://test"},
		},
		{
			name: "empty string",
			s:    "",
			want: []string{},
		},
		{
			name: "trailing semicolon",
			s:    `Hash=abc;Cert="xyz";`,
			want: []string{"Hash=abc", `Cert="xyz"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitXFCCPairs(tt.s)
			assert.Equal(t, len(got), len(tt.want))
			for i := range got {
				assert.Equal(t, got[i], tt.want[i])
			}
		})
	}
}

func TestParseXFCCElement(t *testing.T) {
	tests := []struct {
		name    string
		element string
		want    xfccElement
	}{
		{
			name:    "all fields",
			element: `By=spiffe://test;Hash=abc;Cert="cert";Chain="chain";Subject="CN=test";URI=spiffe://uri;DNS=test.com`,
			want: xfccElement{
				By:      "spiffe://test",
				Hash:    "abc",
				Cert:    "cert",
				Chain:   "chain",
				Subject: "CN=test",
				URI:     "spiffe://uri",
				DNS:     "test.com",
			},
		},
		{
			name:    "quoted values",
			element: `Hash="abc";Cert="xyz"`,
			want: xfccElement{
				Hash: "abc",
				Cert: "xyz",
			},
		},
		{
			name:    "unquoted values",
			element: `Hash=abc;Subject=CN=test`,
			want: xfccElement{
				Hash:    "abc",
				Subject: "CN=test",
			},
		},
		{
			name:    "empty",
			element: "",
			want:    xfccElement{},
		},
		{
			name:    "semicolon in quoted value",
			element: `Hash=abc;Cert="xyz;123";Subject="CN=test;OU=dev"`,
			want: xfccElement{
				Hash:    "abc",
				Cert:    "xyz;123",
				Subject: "CN=test;OU=dev",
			},
		},
		{
			name:    "complex quoted value with multiple special chars",
			element: `Hash=abc;Cert="data;with=semicolon,and=comma";Subject="CN=test"`,
			want: xfccElement{
				Hash:    "abc",
				Cert:    "data;with=semicolon,and=comma",
				Subject: "CN=test",
			},
		},
		{
			name:    "equals in quoted value",
			element: `Hash=abc;Subject="CN=test,OU=dev,O=ACME Inc."`,
			want: xfccElement{
				Hash:    "abc",
				Subject: "CN=test,OU=dev,O=ACME Inc.",
			},
		},
		{
			name:    "multiple equals in quoted cert value",
			element: `Cert="data=with=multiple=equals";Subject="CN=user"`,
			want: xfccElement{
				Cert:    "data=with=multiple=equals",
				Subject: "CN=user",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseXFCCElement(tt.element)
			assert.NilError(t, err)
			assert.DeepEqual(t, got, tt.want)
		})
	}
}
