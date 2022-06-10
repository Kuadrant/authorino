package identity

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/log"

	k8s "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type MTLS struct {
	auth.AuthCredentials

	Name           string
	LabelSelectors map[string]string
	Namespace      string

	rootCerts *x509.CertPool
	k8sClient client.Reader
}

func NewMTLSIdentity(name string, labelSelectors map[string]string, namespace string, k8sClient client.Reader, ctx context.Context) *MTLS {
	mtls := &MTLS{
		AuthCredentials: &auth.AuthCredential{KeySelector: "Basic"},
		Name:            name,
		LabelSelectors:  labelSelectors,
		Namespace:       namespace,
		k8sClient:       k8sClient,
	}
	if err := mtls.loadSecrets(context.TODO()); err != nil {
		log.FromContext(ctx).WithName("mtls").Error(err, credentialsFetchingErrorMsg)
	}
	return mtls
}

// loadSecrets will get the k8s secrets and update the APIKey instance
func (m *MTLS) loadSecrets(ctx context.Context) error {
	opts := []client.ListOption{client.MatchingLabels(m.LabelSelectors)}
	if namespace := m.Namespace; namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	var secretList = &k8s.SecretList{}
	if err := m.k8sClient.List(ctx, secretList, opts...); err != nil {
		return err
	}
	m.rootCerts = x509.NewCertPool()
	for _, secret := range secretList.Items {
		var encodedCert []byte
		if v, foundKey := secret.Data[k8s.TLSCertKey]; foundKey {
			encodedCert = v
		} else if v, foundKey := secret.Data[k8s.ServiceAccountRootCAKey]; foundKey {
			encodedCert = v
		} else {
			continue
		}
		block, _ := pem.Decode(encodedCert)
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			m.rootCerts.AddCert(cert)
		}
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
