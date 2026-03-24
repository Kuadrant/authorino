package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math"
	"math/big"
	"net/url"
	"testing"
	"time"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/expressions/cel"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	k8s "k8s.io/api/core/v1"
	k8s_meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_labels "k8s.io/apimachinery/pkg/labels"
	k8s_types "k8s.io/apimachinery/pkg/types"
	k8s_client "sigs.k8s.io/controller-runtime/pkg/client"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

var (
	testMTLSK8sSecret1, testMTLSK8sSecret2, testMTLSK8sSecret3 *k8s.Secret
	testMTLSK8sClient                                          k8s_client.WithWatch
	testCerts                                                  = map[string]map[string][]byte{}
)

func init() {
	// generate ca certs
	for _, name := range []string{"pets", "cars", "books"} {
		testCerts[name] = make(map[string][]byte)
		testCerts[name]["tls.crt"], testCerts[name]["tls.key"] = issueCertificate(pkix.Name{CommonName: name}, nil, 1, []x509.ExtKeyUsage{})
	}

	// store the ca certs in k8s secrets
	testMTLSK8sSecret1 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "pets", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: testCerts["pets"], Type: k8s.SecretTypeTLS}
	testMTLSK8sSecret2 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "cars", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: testCerts["cars"], Type: k8s.SecretTypeTLS}
	testMTLSK8sSecret3 = &k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "books", Namespace: "ns2", Labels: map[string]string{"app": "all"}}, Data: testCerts["books"], Type: k8s.SecretTypeTLS}
	testMTLSK8sClient = mockK8sClient(testMTLSK8sSecret1, testMTLSK8sSecret2, testMTLSK8sSecret3)

	// generate client certs
	for name, data := range map[string]struct {
		subject     pkix.Name
		caName      string
		days        int
		extKeyUsage []x509.ExtKeyUsage
	}{
		"john": {
			subject:     pkix.Name{CommonName: "john", Country: []string{"UK"}, Locality: []string{"London"}},
			caName:      "pets",
			days:        1,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		"bob": {
			subject:     pkix.Name{CommonName: "bob", Country: []string{"US"}, Locality: []string{"Boston"}},
			caName:      "pets",
			days:        -1,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		"aisha": {
			subject:     pkix.Name{CommonName: "aisha", Country: []string{"PK"}, Locality: []string{"Islamabad"}, Organization: []string{"ACME Inc."}, OrganizationalUnit: []string{"Engineering"}},
			caName:      "cars",
			days:        1,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		"niko": {
			subject:     pkix.Name{CommonName: "niko", Country: []string{"JP"}, Locality: []string{"Osaka"}},
			caName:      "books",
			days:        1,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		"tony": {
			subject:     pkix.Name{CommonName: "tony", Country: []string{"IT"}, Locality: []string{"Rome"}},
			caName:      "pets",
			days:        1,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
	} {
		testCerts[name] = make(map[string][]byte)
		testCerts[name]["tls.crt"], testCerts[name]["tls.key"] = issueCertificate(data.subject, testCerts[data.caName], data.days, data.extKeyUsage)
	}
}

func TestNewMTLSIdentity(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "", "", nil, testMTLSK8sClient, context.TODO())

	assert.Equal(t, mtls.Name, "mtls")
	assert.Equal(t, mtls.LabelSelectors.String(), "app=all")
	assert.Equal(t, mtls.Namespace, "")
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/pets"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns1/cars"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns2/books"]
	assert.Check(t, exists)
}

func TestNewMTLSIdentitySingleNamespace(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())

	assert.Equal(t, mtls.Name, "mtls")
	assert.Equal(t, mtls.LabelSelectors.String(), "app=all")
	assert.Equal(t, mtls.Namespace, "ns1")
	assert.Equal(t, len(mtls.rootCerts), 2)
	_, exists = mtls.rootCerts["ns1/pets"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns1/cars"]
	assert.Check(t, exists)
	_, exists = mtls.rootCerts["ns2/books"]
	assert.Check(t, !exists)
}

func TestMTLSGetK8sSecretLabelSelectors(t *testing.T) {
	selector, _ := k8s_labels.Parse("app=test")
	mtls := NewMTLSIdentity("mtls", selector, "", "", nil, testMTLSK8sClient, context.TODO())
	assert.Equal(t, mtls.GetK8sSecretLabelSelectors().String(), "app=test")
}

func TestMTLSAddK8sSecretBasedIdentity(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())

	assert.Equal(t, len(mtls.rootCerts), 2)

	newSecretWithinScope := k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "foo", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: testCerts["cars"], Type: k8s.SecretTypeTLS}
	mtls.AddK8sSecretBasedIdentity(context.TODO(), newSecretWithinScope)
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/foo"]
	assert.Check(t, exists)

	newSecretOutOfScope := k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "bar", Namespace: "ns2", Labels: map[string]string{"app": "all"}}, Data: testCerts["cars"], Type: k8s.SecretTypeTLS}
	mtls.AddK8sSecretBasedIdentity(context.TODO(), newSecretOutOfScope)
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/bar"]
	assert.Check(t, !exists)

	newSecretInvalid := k8s.Secret{ObjectMeta: k8s_meta.ObjectMeta{Name: "inv", Namespace: "ns1", Labels: map[string]string{"app": "all"}}, Data: map[string][]byte{}, Type: k8s.SecretTypeTLS}
	mtls.AddK8sSecretBasedIdentity(context.TODO(), newSecretInvalid)
	assert.Equal(t, len(mtls.rootCerts), 3)
	_, exists = mtls.rootCerts["ns1/inv"]
	assert.Check(t, !exists)
}

func TestMTLSRevokeK8sSecretBasedIdentity(t *testing.T) {
	var exists bool

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())

	assert.Equal(t, len(mtls.rootCerts), 2)

	// revoke existing trusted ca cert
	mtls.RevokeK8sSecretBasedIdentity(context.TODO(), k8s_types.NamespacedName{Namespace: "ns1", Name: "pets"})
	assert.Equal(t, len(mtls.rootCerts), 1)
	_, exists = mtls.rootCerts["ns1/pets"]
	assert.Check(t, !exists)

	mtls.AddK8sSecretBasedIdentity(context.TODO(), *testMTLSK8sSecret1)
	assert.Equal(t, len(mtls.rootCerts), 2)

	// revoke non-existing trusted ca cert
	mtls.RevokeK8sSecretBasedIdentity(context.TODO(), k8s_types.NamespacedName{Namespace: "ns1", Name: "foo"})
	assert.Equal(t, len(mtls.rootCerts), 2)

	// revoke trusted ca cert out of scope
	mtls.RevokeK8sSecretBasedIdentity(context.TODO(), k8s_types.NamespacedName{Namespace: "ns2", Name: "books"})
	assert.Equal(t, len(mtls.rootCerts), 2)
}

func TestCall(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// john (ca: pets)
	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["john"]["tls.crt"])),
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)

	// aisha (ca: cars)
	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["aisha"]["tls.crt"])),
			},
		},
	})
	obj, err = mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["PK"],"Organization":["ACME Inc."],"OrganizationalUnit":["Engineering"],"Locality":["Islamabad"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"aisha","Names":[{"Type":[2,5,4,6],"Value":"PK"},{"Type":[2,5,4,7],"Value":"Islamabad"},{"Type":[2,5,4,10],"Value":"ACME Inc."},{"Type":[2,5,4,11],"Value":"Engineering"},{"Type":[2,5,4,3],"Value":"aisha"}],"ExtraNames":null}`)
}

func TestCallUnknownAuthority(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// niko (ca: books)
	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["niko"]["tls.crt"])),
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "certificate signed by unknown authority")
}

func TestCallMissingClientCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "client certificate is missing")
}

func TestCallInvalidClientCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: `-----BEGIN%20CERTIFICATE-----%0Ablahblohbleh%3D%3D%0A-----END%20CERTIFICATE-----%0A`,
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "invalid client certificate")
}

func TestCallExpiredClientCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// bob (ca: pets / client cert expired on 2023-01-16)
	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["bob"]["tls.crt"])),
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "certificate has expired or is not yet valid")
}

func TestExtendedKeyUsageMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// tony (ca: pets / extKeyUsage: server auth)
	pipeline.EXPECT().GetRequest().Return(&envoy_auth.CheckRequest{
		Attributes: &envoy_auth.AttributeContext{
			Source: &envoy_auth.AttributeContext_Peer{
				Certificate: url.QueryEscape(string(testCerts["tony"]["tls.crt"])),
			},
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "certificate specifies an incompatible key usage")
}

func TestCallWithXFCCHeader(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	// Create MTLS evaluator configured to extract from XFCC header
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "x-forwarded-client-cert", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// john (ca: pets) - certificate in XFCC header
	xfccValue := `Hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;Cert="` + url.QueryEscape(string(testCerts["john"]["tls.crt"])) + `";Subject="CN=john,L=London,C=UK"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-forwarded-client-cert": xfccValue,
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)

	// aisha (ca: cars) - certificate in XFCC header
	xfccValue = `Hash=abc123;Cert="` + url.QueryEscape(string(testCerts["aisha"]["tls.crt"])) + `";Subject="CN=aisha,L=Islamabad,O=ACME Inc.,OU=Engineering,C=PK"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-forwarded-client-cert": xfccValue,
		},
	})
	obj, err = mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["PK"],"Organization":["ACME Inc."],"OrganizationalUnit":["Engineering"],"Locality":["Islamabad"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"aisha","Names":[{"Type":[2,5,4,6],"Value":"PK"},{"Type":[2,5,4,7],"Value":"Islamabad"},{"Type":[2,5,4,10],"Value":"ACME Inc."},{"Type":[2,5,4,11],"Value":"Engineering"},{"Type":[2,5,4,3],"Value":"aisha"}],"ExtraNames":null}`)
}

func TestCallWithXFCCHeaderCaseInsensitive(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	// Create MTLS evaluator configured to extract from XFCC header
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "x-forwarded-client-cert", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// john (ca: pets) - certificate in XFCC header with mixed case keys
	xfccValue := `hash=468ed33be74eee6556d90c0149c1309e9ba61d6425303443c0748a02dd8de688;cert="` + url.QueryEscape(string(testCerts["john"]["tls.crt"])) + `";subject="CN=john,L=London,C=UK"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-forwarded-client-cert": xfccValue,
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)

	// aisha (ca: cars) - certificate in XFCC header with different mixed case
	xfccValue = `HASH=abc123;CERT="` + url.QueryEscape(string(testCerts["aisha"]["tls.crt"])) + `";SUBJECT="CN=aisha,L=Islamabad,O=ACME Inc.,OU=Engineering,C=PK"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-forwarded-client-cert": xfccValue,
		},
	})
	obj, err = mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["PK"],"Organization":["ACME Inc."],"OrganizationalUnit":["Engineering"],"Locality":["Islamabad"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"aisha","Names":[{"Type":[2,5,4,6],"Value":"PK"},{"Type":[2,5,4,7],"Value":"Islamabad"},{"Type":[2,5,4,10],"Value":"ACME Inc."},{"Type":[2,5,4,11],"Value":"Engineering"},{"Type":[2,5,4,3],"Value":"aisha"}],"ExtraNames":null}`)
}

func TestCallWithXFCCHeaderCertInChainField(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "x-forwarded-client-cert", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// Certificate in Chain field (fallback when Cert is not present)
	xfccValue := `Hash=abc;Chain="` + url.QueryEscape(string(testCerts["john"]["tls.crt"])) + `"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-forwarded-client-cert": xfccValue,
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)
}

func TestCallWithXFCCHeaderMissing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "x-forwarded-client-cert", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// XFCC header not present
	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "header x-forwarded-client-cert not found")
}

func TestCallWithXFCCHeaderInvalidCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "x-forwarded-client-cert", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// Invalid certificate in XFCC header
	xfccValue := `Hash=abc;Cert="invalid-cert-data"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-forwarded-client-cert": xfccValue,
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "invalid client certificate")
}

func TestCallWithXFCCHeaderUnknownAuthority(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "x-forwarded-client-cert", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// niko (ca: books) - not trusted in ns1
	xfccValue := `Hash=abc;Cert="` + url.QueryEscape(string(testCerts["niko"]["tls.crt"])) + `"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-forwarded-client-cert": xfccValue,
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "certificate signed by unknown authority")
}

func TestCallWithCustomXFCCHeaderName(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")
	// Use custom header name
	mtls := NewMTLSIdentity("mtls", selector, "ns1", "x-custom-client-cert", nil, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	xfccValue := `Cert="` + url.QueryEscape(string(testCerts["john"]["tls.crt"])) + `"`

	pipeline.EXPECT().GetHttp().Return(&envoy_auth.AttributeContext_HttpRequest{
		Headers: map[string]string{
			"x-custom-client-cert": xfccValue,
		},
	})
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)
}

func TestCallWithExpression(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")

	// Create CEL expression to extract certificate from authorization JSON
	expression, err := cel.NewExpression("source.certificate")
	assert.NilError(t, err)

	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", expression, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// john (ca: pets) - certificate in authorization JSON at source.certificate
	authJSON := `{"source":{"certificate":"` + url.QueryEscape(string(testCerts["john"]["tls.crt"])) + `"}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)

	// aisha (ca: cars) - certificate in authorization JSON
	authJSON = `{"source":{"certificate":"` + url.QueryEscape(string(testCerts["aisha"]["tls.crt"])) + `"}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err = mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["PK"],"Organization":["ACME Inc."],"OrganizationalUnit":["Engineering"],"Locality":["Islamabad"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"aisha","Names":[{"Type":[2,5,4,6],"Value":"PK"},{"Type":[2,5,4,7],"Value":"Islamabad"},{"Type":[2,5,4,10],"Value":"ACME Inc."},{"Type":[2,5,4,11],"Value":"Engineering"},{"Type":[2,5,4,3],"Value":"aisha"}],"ExtraNames":null}`)
}

func TestCallWithExpressionCustomPath(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")

	// Create CEL expression to extract from custom path
	expression, err := cel.NewExpression("request.http.headers['x-ssl-client-cert']")
	assert.NilError(t, err)

	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", expression, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// Certificate in custom header location
	authJSON := `{"request":{"http":{"headers":{"x-ssl-client-cert":"` + url.QueryEscape(string(testCerts["john"]["tls.crt"])) + `"}}}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)
}

func TestCallWithExpressionMissingCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")

	expression, err := cel.NewExpression("source.certificate")
	assert.NilError(t, err)

	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", expression, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// Certificate field missing from authorization JSON
	authJSON := `{"source":{}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	// CEL expression returns "no such key" error when the field is missing
	assert.ErrorContains(t, err, "failed to obtain the client certificate")
}

func TestCallWithExpressionInvalidCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")

	expression, err := cel.NewExpression("source.certificate")
	assert.NilError(t, err)

	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", expression, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// Invalid certificate data
	authJSON := `{"source":{"certificate":"invalid-cert-data"}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "invalid client certificate")
}

func TestCallWithExpressionUnknownAuthority(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")

	expression, err := cel.NewExpression("source.certificate")
	assert.NilError(t, err)

	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", expression, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// niko (ca: books) - not trusted in ns1
	authJSON := `{"source":{"certificate":"` + url.QueryEscape(string(testCerts["niko"]["tls.crt"])) + `"}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "certificate signed by unknown authority")
}

func TestCallWithExpressionExpiredCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")

	expression, err := cel.NewExpression("source.certificate")
	assert.NilError(t, err)

	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", expression, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// bob (ca: pets / client cert expired)
	authJSON := `{"source":{"certificate":"` + url.QueryEscape(string(testCerts["bob"]["tls.crt"])) + `"}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.Check(t, obj == nil)
	assert.ErrorContains(t, err, "certificate has expired or is not yet valid")
}

func TestCallWithExpressionComplexPath(t *testing.T) {
	var data []byte

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	selector, _ := k8s_labels.Parse("app=all")

	// Create CEL expression with conditional logic to choose between two sources
	expression, err := cel.NewExpression("has(metadata.tls_cert) ? metadata.tls_cert : source.certificate")
	assert.NilError(t, err)

	mtls := NewMTLSIdentity("mtls", selector, "ns1", "", expression, testMTLSK8sClient, context.TODO())
	pipeline := mock_auth.NewMockAuthPipeline(ctrl)

	// Certificate in metadata (preferred path)
	authJSON := `{"metadata":{"tls_cert":"` + url.QueryEscape(string(testCerts["john"]["tls.crt"])) + `"},"source":{"certificate":"` + url.QueryEscape(string(testCerts["aisha"]["tls.crt"])) + `"}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err := mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	// Should use john's cert from metadata, not aisha's from source
	assert.Equal(t, string(data), `{"Country":["UK"],"Organization":null,"OrganizationalUnit":null,"Locality":["London"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"john","Names":[{"Type":[2,5,4,6],"Value":"UK"},{"Type":[2,5,4,7],"Value":"London"},{"Type":[2,5,4,3],"Value":"john"}],"ExtraNames":null}`)

	// Certificate only in source (fallback path)
	authJSON = `{"source":{"certificate":"` + url.QueryEscape(string(testCerts["aisha"]["tls.crt"])) + `"}}`

	pipeline.EXPECT().GetAuthorizationJSON().Return(authJSON)
	obj, err = mtls.Call(pipeline, context.TODO())
	assert.NilError(t, err)
	data, _ = json.Marshal(obj)
	// Should use aisha's cert from source
	assert.Equal(t, string(data), `{"Country":["PK"],"Organization":["ACME Inc."],"OrganizationalUnit":["Engineering"],"Locality":["Islamabad"],"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"aisha","Names":[{"Type":[2,5,4,6],"Value":"PK"},{"Type":[2,5,4,7],"Value":"Islamabad"},{"Type":[2,5,4,10],"Value":"ACME Inc."},{"Type":[2,5,4,11],"Value":"Engineering"},{"Type":[2,5,4,3],"Value":"aisha"}],"ExtraNames":null}`)
}

func issueCertificate(subject pkix.Name, ca map[string][]byte, days int, extKeyUsage []x509.ExtKeyUsage) ([]byte, []byte) {
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	isCA := ca == nil
	cert := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, days),
		IsCA:                  isCA,
		ExtKeyUsage:           extKeyUsage,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: isCA,
	}
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	privKey := key
	parent := cert
	if !isCA {
		parent = decodeCertificate(ca["tls.crt"])
		privKey = decodePrivateKey(ca["tls.key"])
		cert.KeyUsage = x509.KeyUsageDigitalSignature
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, parent, &key.PublicKey, privKey)
	return encodeCertificate(certBytes), encodePrivateKey(key)
}

func encodeCertificate(cert []byte) []byte {
	certPEM := new(bytes.Buffer)
	_ = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return certPEM.Bytes()
}

func encodePrivateKey(key *rsa.PrivateKey) []byte {
	keyPEM := new(bytes.Buffer)
	_ = pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return keyPEM.Bytes()
}

func decodePrivateKey(encodedCert []byte) (key *rsa.PrivateKey) {
	for len(encodedCert) > 0 {
		var block *pem.Block
		block, encodedCert = pem.Decode(encodedCert)
		if block == nil {
			break
		}
		if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
			continue
		}
		var err error
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
	}
	return key
}
