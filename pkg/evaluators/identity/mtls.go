package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/log"

	k8s "k8s.io/api/core/v1"
	k8s_labels "k8s.io/apimachinery/pkg/labels"
	k8s_types "k8s.io/apimachinery/pkg/types"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
)

type MTLS struct {
	auth.AuthCredentials

	Name             string
	LabelSelectors   k8s_labels.Selector
	Namespace        string
	XFCCHeader       string            // name of the XFCC HTTP header (e.g., "x-forwarded-client-cert")
	ClientCertHeader string            // name of the Client-Cert HTTP header (RFC 9440)
	Expression       expressions.Value // CEL expression for extracting the certificate from the authorization JSON

	rootCerts map[string]*x509.Certificate
	mutex     sync.RWMutex
	k8sClient k8s_client.Reader
}

func NewMTLSIdentity(name string, labelSelectors k8s_labels.Selector, namespace string, xfccHeader string, clientCertHeader string, expression expressions.Value, k8sClient k8s_client.Reader, ctx context.Context) *MTLS {
	mtls := &MTLS{
		AuthCredentials:  &auth.AuthCredential{KeySelector: "Basic"},
		Name:             name,
		LabelSelectors:   labelSelectors,
		Namespace:        namespace,
		XFCCHeader:       xfccHeader,
		ClientCertHeader: clientCertHeader,
		Expression:       expression,
		rootCerts:        make(map[string]*x509.Certificate),
		k8sClient:        k8sClient,
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
	if m.XFCCHeader != "" {
		// Extract from XFCC header (Envoy format)
		pemEncodedCert, err = m.extractFromXFCCHeader(pipeline)
		if err != nil {
			return nil, err
		}
	} else if m.ClientCertHeader != "" {
		// Extract from Client-Cert header (RFC 9440)
		pemEncodedCert, err = m.extractFromClientCertHeader(pipeline)
		if err != nil {
			return nil, err
		}
	} else if m.Expression != nil {
		// Extract from CEL expression
		pemEncodedCert, err = m.extractFromExpression(pipeline)
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

// extractFromXFCCHeader extracts the certificate from an XFCC HTTP header (Envoy format)
func (m *MTLS) extractFromXFCCHeader(pipeline auth.AuthPipeline) (string, error) {
	headers := pipeline.GetHttp().GetHeaders()
	headerValue, err := getXFCCHeaderFromRequest(headers, m.XFCCHeader)
	if err != nil {
		return "", fmt.Errorf("failed to extract XFCC header: %w", err)
	}

	pemCert, err := extractClientCertFromXFCC(headerValue)
	if err != nil {
		return "", fmt.Errorf("failed to extract certificate from XFCC: %w", err)
	}

	return pemCert, nil
}

// extractFromClientCertHeader extracts the certificate from a Client-Cert HTTP header (RFC 9440)
func (m *MTLS) extractFromClientCertHeader(pipeline auth.AuthPipeline) (string, error) {
	headers := pipeline.GetHttp().GetHeaders()

	// Client-Cert header name is case-insensitive
	headerName := strings.ToLower(m.ClientCertHeader)
	headerValue, ok := headers[headerName]
	if !ok {
		return "", fmt.Errorf("header %s not found in request", m.ClientCertHeader)
	}

	// RFC 9440: Extract and convert DER certificate to PEM
	pemCert, err := extractClientCertFromRFC9440(headerValue)
	if err != nil {
		return "", fmt.Errorf("failed to extract certificate from Client-Cert header: %w", err)
	}

	return pemCert, nil
}

// extractFromExpression extracts the certificate from a CEL expression
func (m *MTLS) extractFromExpression(pipeline auth.AuthPipeline) (string, error) {
	cert, err := m.Expression.ResolveFor(pipeline.GetAuthorizationJSON())
	if err != nil {
		return "", fmt.Errorf("failed to obtain the client certificate: %w", err)
	}
	urlEncodedCert, ok := cert.(string)
	if !ok || urlEncodedCert == "" {
		return "", fmt.Errorf("invalid client certificate")
	}
	return urlDecodeCertificate(urlEncodedCert)
}

// extractFromSourceCertificate extracts the certificate from source.certificate (default/legacy behavior)
func (m *MTLS) extractFromSourceCertificate(pipeline auth.AuthPipeline) (string, error) {
	urlEncodedCert := pipeline.GetRequest().Attributes.Source.GetCertificate()
	if urlEncodedCert == "" {
		return "", fmt.Errorf("client certificate is missing")
	}
	return urlDecodeCertificate(urlEncodedCert)
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

func urlDecodeCertificate(urlEncodedCert string) (string, error) {
	pemEncodedCert, err := url.QueryUnescape(urlEncodedCert)
	if err != nil {
		return "", fmt.Errorf("invalid client certificate")
	}

	return pemEncodedCert, nil
}
