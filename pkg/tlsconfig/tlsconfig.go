package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"strings"
)

var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func buildCipherLookup() map[string]uint16 {
	m := make(map[string]uint16)
	for _, cs := range tls.CipherSuites() {
		m[cs.Name] = cs.ID
	}
	for _, cs := range tls.InsecureCipherSuites() {
		m[cs.Name] = cs.ID
	}
	return m
}

var cipherLookup = buildCipherLookup()

func ParseMinVersion(s string) (uint16, error) {
	if s == "" {
		return tls.VersionTLS12, nil
	}
	v, ok := tlsVersions[s]
	if !ok {
		return 0, fmt.Errorf("unknown TLS version %q", s)
	}
	return v, nil
}

func ParseMaxVersion(s string) (uint16, error) {
	if s == "" {
		return 0, nil
	}
	v, ok := tlsVersions[s]
	if !ok {
		return 0, fmt.Errorf("unknown TLS version %q", s)
	}
	return v, nil
}

func ParseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		id, ok := cipherLookup[strings.TrimSpace(name)]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite %q", name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func BuildTLSConfig(minVersion, maxVersion string, cipherSuites []string) (*tls.Config, error) {
	minVer, err := ParseMinVersion(minVersion)
	if err != nil {
		return nil, err
	}
	maxVer, err := ParseMaxVersion(maxVersion)
	if err != nil {
		return nil, err
	}
	if maxVer != 0 && minVer > maxVer {
		return nil, fmt.Errorf("TLS min version (%s) must not exceed max version (%s)", minVersion, maxVersion)
	}
	suites, err := ParseCipherSuites(cipherSuites)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   minVer,
		MaxVersion:   maxVer,
		CipherSuites: suites,
	}, nil
}
