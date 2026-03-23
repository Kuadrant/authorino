package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/log"

	k8s "k8s.io/api/core/v1"
	k8s_labels "k8s.io/apimachinery/pkg/labels"
	k8s_types "k8s.io/apimachinery/pkg/types"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
)

type MTLS struct {
	auth.AuthCredentials

	Name           string
	LabelSelectors k8s_labels.Selector
	Namespace      string
	HeaderName     string // HTTP header name for XFCC (e.g., "x-forwarded-client-cert")
	AttributePath  string // Attribute path in CheckRequest (for advanced use cases)

	rootCerts map[string]*x509.Certificate
	mutex     sync.RWMutex
	k8sClient k8s_client.Reader
}

func NewMTLSIdentity(name string, labelSelectors k8s_labels.Selector, namespace string, headerName string, attributePath string, k8sClient k8s_client.Reader, ctx context.Context) *MTLS {
	mtls := &MTLS{
		AuthCredentials: &auth.AuthCredential{KeySelector: "Basic"},
		Name:            name,
		LabelSelectors:  labelSelectors,
		Namespace:       namespace,
		HeaderName:      headerName,
		AttributePath:   attributePath,
		rootCerts:       make(map[string]*x509.Certificate),
		k8sClient:       k8sClient,
	}
	if err := mtls.loadSecrets(context.TODO()); err != nil {
		log.FromContext(ctx).WithName("mtls").Error(err, credentialsFetchingErrorMsg)
	}
	return mtls
}

// loadSecrets will load the matching k8s secrets from the cluster to the cache of trusted root CAs
func (m *MTLS) loadSecrets(ctx context.Context) error {
	opts := []k8s_client.ListOption{k8s_client.MatchingLabelsSelector{Selector: m.LabelSelectors}}
	if namespace := m.Namespace; namespace != "" {
		opts = append(opts, k8s_client.InNamespace(namespace))
	}
	var secretList = &k8s.SecretList{}
	if err := m.k8sClient.List(ctx, secretList, opts...); err != nil {
		return err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, secret := range secretList.Items {
		secretName := k8s_types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
		if cert := certificateFromSecret(secret); cert != nil {
			m.rootCerts[secretName.String()] = cert
		}
	}

	return nil
}

func (m *MTLS) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	var pemEncodedCert string
	var err error

	// Extract certificate based on configured source
	if m.HeaderName != "" {
		// Extract from HTTP header (XFCC)
		pemEncodedCert, err = m.extractFromHeader(pipeline)
		if err != nil {
			return nil, err
		}
	} else if m.AttributePath != "" {
		// Extract from custom attribute path
		pemEncodedCert, err = m.extractFromAttribute(pipeline)
		if err != nil {
			return nil, err
		}
	} else {
		// Default: extract from source.certificate (backward compatibility)
		pemEncodedCert, err = m.extractFromSourceCertificate(pipeline)
		if err != nil {
			return nil, err
		}
	}

	// Decode PEM certificate
	cert := decodeCertificate([]byte(pemEncodedCert))
	if cert == nil {
		return nil, fmt.Errorf("invalid client certificate")
	}

	// Validate certificate against trusted CAs
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	certs := x509.NewCertPool()
	for _, cert := range m.rootCerts {
		certs.AddCert(cert)
	}

	if _, err := cert.Verify(x509.VerifyOptions{Roots: certs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, err
	}

	return cert.Subject, nil
}

// extractFromHeader extracts the certificate from an HTTP header (e.g., XFCC)
func (m *MTLS) extractFromHeader(pipeline auth.AuthPipeline) (string, error) {
	headers := pipeline.GetHttp().GetHeaders()
	headerValue, err := getXFCCHeaderFromRequest(headers, m.HeaderName)
	if err != nil {
		return "", fmt.Errorf("failed to extract XFCC header: %w", err)
	}

	pemCert, err := extractClientCertFromXFCC(headerValue)
	if err != nil {
		return "", fmt.Errorf("failed to extract certificate from XFCC: %w", err)
	}

	return pemCert, nil
}

// extractFromAttribute extracts the certificate from a custom attribute path
func (m *MTLS) extractFromAttribute(_ auth.AuthPipeline) (string, error) {
	// For future implementation: use AttributePath to navigate CheckRequest
	// For now, this is a placeholder for advanced use cases
	return "", fmt.Errorf("custom attribute path extraction not yet implemented")
}

// extractFromSourceCertificate extracts the certificate from source.certificate (default/legacy behavior)
func (m *MTLS) extractFromSourceCertificate(pipeline auth.AuthPipeline) (string, error) {
	urlEncodedCert := pipeline.GetRequest().Attributes.Source.GetCertificate()
	if urlEncodedCert == "" {
		return "", fmt.Errorf("client certificate is missing")
	}

	pemEncodedCert, err := url.QueryUnescape(urlEncodedCert)
	if err != nil {
		return "", fmt.Errorf("invalid client certificate")
	}

	return pemEncodedCert, nil
}

// impl:K8sSecretBasedIdentityConfigEvaluator

func (m *MTLS) GetK8sSecretLabelSelectors() k8s_labels.Selector {
	return m.LabelSelectors
}

func (m *MTLS) AddK8sSecretBasedIdentity(ctx context.Context, new k8s.Secret) {
	if !m.withinScope(new.GetNamespace()) {
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	secretName := k8s_types.NamespacedName{Namespace: new.Namespace, Name: new.Name}.String()
	newCert := certificateFromSecret(new)
	logger := log.FromContext(ctx).WithName("mtls")

	if newCert == nil {
		logger.V(1).Info("invalid root ca cert")
		return
	}

	// updating existing
	if currentCert, found := m.rootCerts[secretName]; found {
		logger := log.FromContext(ctx).WithName("mtls")
		if sha256.Sum224(currentCert.Raw) != sha256.Sum224(newCert.Raw) {
			m.rootCerts[secretName] = newCert
			logger.V(1).Info("trusted root ca updated")
		} else {
			logger.V(1).Info("trusted root ca unchanged")
		}
		return
	}

	m.rootCerts[secretName] = newCert
	logger.V(1).Info("trusted root ca added")
}

func (m *MTLS) RevokeK8sSecretBasedIdentity(ctx context.Context, deleted k8s_types.NamespacedName) {
	if !m.withinScope(deleted.Namespace) {
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	secretName := deleted.String()

	if _, found := m.rootCerts[secretName]; found {
		delete(m.rootCerts, secretName)
		log.FromContext(ctx).WithName("mtls").V(1).Info("trusted root ca deleted")
	}
}

func (m *MTLS) withinScope(namespace string) bool {
	return m.Namespace == "" || m.Namespace == namespace
}

func certificateFromSecret(secret k8s.Secret) (cert *x509.Certificate) {
	var encodedCert []byte
	if v, hasTLSCert := secret.Data[k8s.TLSCertKey]; hasTLSCert {
		encodedCert = v
	} else if v, hasCACert := secret.Data[k8s.ServiceAccountRootCAKey]; hasCACert {
		encodedCert = v
	} else {
		return nil
	}
	return decodeCertificate(encodedCert)
}

func decodeCertificate(encodedCert []byte) (cert *x509.Certificate) {
	for len(encodedCert) > 0 {
		var block *pem.Block
		block, encodedCert = pem.Decode(encodedCert)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		var err error
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
	}
	return cert
}
