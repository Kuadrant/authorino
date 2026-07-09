package tlsconfig

import (
	"crypto/tls"
	"testing"
)

func TestParseMinVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"", tls.VersionTLS12, false},
		{"1.0", tls.VersionTLS10, false},
		{"1.1", tls.VersionTLS11, false},
		{"1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseMinVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMinVersion(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseMinVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseMaxVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"", 0, false},
		{"1.0", tls.VersionTLS10, false},
		{"1.1", tls.VersionTLS11, false},
		{"1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseMaxVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMaxVersion(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseMaxVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseCipherSuites(t *testing.T) {
	t.Run("empty returns nil", func(t *testing.T) {
		ids, err := ParseCipherSuites(nil)
		if err != nil {
			t.Fatal(err)
		}
		if ids != nil {
			t.Errorf("expected nil, got %v", ids)
		}
	})

	t.Run("valid IANA names", func(t *testing.T) {
		names := []string{
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		}
		ids, err := ParseCipherSuites(names)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 2 {
			t.Fatalf("expected 2 cipher suites, got %d", len(ids))
		}
		if ids[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Errorf("expected TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, got %v", ids[0])
		}
		if ids[1] != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
			t.Errorf("expected TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, got %v", ids[1])
		}
	})

	t.Run("unknown cipher returns error", func(t *testing.T) {
		_, err := ParseCipherSuites([]string{"INVALID_CIPHER"})
		if err == nil {
			t.Error("expected error for unknown cipher")
		}
	})
}

func TestBuildTLSConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := BuildTLSConfig("", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected MinVersion TLS 1.2, got %v", cfg.MinVersion)
		}
		if cfg.MaxVersion != 0 {
			t.Errorf("expected MaxVersion 0 (no limit), got %v", cfg.MaxVersion)
		}
		if cfg.CipherSuites != nil {
			t.Errorf("expected nil CipherSuites, got %v", cfg.CipherSuites)
		}
	})

	t.Run("explicit config", func(t *testing.T) {
		cfg, err := BuildTLSConfig("1.2", "1.3", []string{
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected MinVersion TLS 1.2, got %v", cfg.MinVersion)
		}
		if cfg.MaxVersion != tls.VersionTLS13 {
			t.Errorf("expected MaxVersion TLS 1.3, got %v", cfg.MaxVersion)
		}
		if len(cfg.CipherSuites) != 1 {
			t.Fatalf("expected 1 cipher suite, got %d", len(cfg.CipherSuites))
		}
	})

	t.Run("invalid min version", func(t *testing.T) {
		_, err := BuildTLSConfig("invalid", "", nil)
		if err == nil {
			t.Error("expected error for invalid version")
		}
	})

	t.Run("invalid max version", func(t *testing.T) {
		_, err := BuildTLSConfig("", "invalid", nil)
		if err == nil {
			t.Error("expected error for invalid version")
		}
	})

	t.Run("invalid cipher", func(t *testing.T) {
		_, err := BuildTLSConfig("1.2", "", []string{"INVALID"})
		if err == nil {
			t.Error("expected error for invalid cipher")
		}
	})

	t.Run("min version exceeds max version", func(t *testing.T) {
		_, err := BuildTLSConfig("1.3", "1.2", nil)
		if err == nil {
			t.Error("expected error when min version exceeds max version")
		}
	})
}
