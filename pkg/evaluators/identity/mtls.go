package identity

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/log"

	k8s "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"
)

type MTLS struct {
	auth.AuthCredentials

	Name           string
	LabelSelectors map[string]string
	Namespace      string

	rootCerts *x509.CertPool
	mutex     sync.Mutex
	k8sClient k8s_client.Reader
}

func NewMTLSIdentity(name string, labelSelectors map[string]string, namespace string, k8sClient k8s_client.Reader, ctx context.Context) *MTLS {
	mtls := &MTLS{
		AuthCredentials: &auth.AuthCredential{KeySelector: "Basic"},
		Name:            name,
		LabelSelectors:  labelSelectors,
		Namespace:       namespace,
		rootCerts:       x509.NewCertPool(),
		k8sClient:       k8sClient,
	}
	if err := mtls.loadSecrets(context.TODO()); err != nil {
		log.FromContext(ctx).WithName("mtls").Error(err, credentialsFetchingErrorMsg)
	}
	return mtls
}

// loadSecrets will load the matching k8s secrets from the cluster to the cache of trusted root CAs
func (m *MTLS) loadSecrets(ctx context.Context) error {
	opts := []k8s_client.ListOption{k8s_client.MatchingLabels(m.LabelSelectors)}
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
		m.appendK8sSecretBasedIdentity(secret)
	}

	return nil
}

func (m *MTLS) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	var cert *x509.Certificate
	var err error

	urlEncodedCert := pipeline.GetRequest().Attributes.Source.GetCertificate()
	if urlEncodedCert == "" {
		return nil, fmt.Errorf("client certificate is missing")
	}
	pemEncodedCert, err := url.QueryUnescape(urlEncodedCert)
	if err != nil {
		return nil, fmt.Errorf("invalid client certificate")
	}

	block, _ := pem.Decode([]byte(pemEncodedCert))

	if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}

	if _, err := cert.Verify(x509.VerifyOptions{Roots: m.rootCerts}); err != nil {
		return nil, err
	}

	return cert.Subject, nil
}

// impl:K8sSecretBasedIdentityConfigEvaluator

func (m *MTLS) GetK8sSecretLabelSelectors() map[string]string {
	return m.LabelSelectors
}

// AddK8sSecretBasedIdentity refreshes the cache of trusted root CA certs by reloading the k8s secrets from the cluster
func (m *MTLS) AddK8sSecretBasedIdentity(ctx context.Context, new k8s.Secret) {
	m.refreshK8sSecretBasedIdentity(ctx, k8s_types.NamespacedName{Namespace: new.Namespace, Name: new.Name})
}

// RevokeK8sSecretBasedIdentity refreshes the cache of trusted root CA certs by reloading the k8s secrets from the cluster
func (m *MTLS) RevokeK8sSecretBasedIdentity(ctx context.Context, deleted k8s_types.NamespacedName) {
	m.refreshK8sSecretBasedIdentity(ctx, deleted)
}

func (m *MTLS) withinScope(namespace string) bool {
	return m.Namespace == "" || m.Namespace == namespace
}

// Appends the K8s Secret to the cache of trusted root CAs
// Caution! This function is not thread-safe. Make sure to acquire a lock before calling it.
func (m *MTLS) appendK8sSecretBasedIdentity(secret v1.Secret) bool {
	var encodedCert []byte

	if v, hasTLSCert := secret.Data[k8s.TLSCertKey]; hasTLSCert {
		encodedCert = v
	} else if v, hasCACert := secret.Data[k8s.ServiceAccountRootCAKey]; hasCACert {
		encodedCert = v
	} else {
		return false
	}

	return m.rootCerts.AppendCertsFromPEM(encodedCert)
}

func (m *MTLS) refreshK8sSecretBasedIdentity(ctx context.Context, secret k8s_types.NamespacedName) {
	if !m.withinScope(secret.Namespace) {
		return
	}

	logger := log.FromContext(ctx).WithName("mtls").WithValues("secret", secret.String())

	current := m.rootCerts
	m.rootCerts = x509.NewCertPool()
	if err := m.loadSecrets(ctx); err != nil {
		logger.Error(err, "failed to refresh trusted root ca certs")
		// rollback
		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.rootCerts = current
		return
	}

	logger.V(1).Info("trusted root ca cert refreshed")
}
