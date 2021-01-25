package controllers

import (
	"context"
	"testing"

	"github.com/3scale-labs/authorino/api/v1beta1"
	"github.com/3scale-labs/authorino/pkg/cache"
	"gotest.tools/assert"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	service = v1beta1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "config.authorino.3scale.net/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service1",
			Namespace: "authorino",
		},
		Spec: v1beta1.ServiceSpec{
			Hosts: []string{"echo-api"},
			Identity: []*v1beta1.Identity{
				{
					Name: "keycloak",
					Oidc: &v1beta1.Identity_OidcConfig{
						Endpoint: "http://keycloak:8080/auth/realms/ostia",
					},
				},
			},
			Metadata: []*v1beta1.Metadata{
				{
					UserInfo: &v1beta1.Metadata_UserInfo{
						IdentitySource: "keycloak",
						Credentials: &v1.LocalObjectReference{
							Name: "secret",
						},
					},
				},
				{
					UMA: &v1beta1.Metadata_UMA{
						IdentitySource: "keycloak",
						Credentials: &v1.LocalObjectReference{
							Name: "secret",
						},
					},
				},
			},
			Authorization: []*v1beta1.Authorization{
				{
					OPAPolicy: &v1beta1.Authorization_OPAPolicy{
						Endpoint: "http://opa:8181",
						UUID:     "8fa79d93-0f93-4e23-8c2a-666be266cad1",
						InlineRego: `allow {
            http_request.method == "GET"
            path = ["pets"]
          }

          allow {
            http_request.method == "GET"
            own_resource
          }

          allow {
            http_request.method == "GET"
            path = ["stats"]
            is_admin
          }

          own_resource {
            some petid
            path = ["pets", petid]
            resource := object.get(metadata, "uma", [])[0]
            owner := object.get(object.get(resource, "owner", {}), "id", "")
            subject := object.get(identity, "sub", object.get(identity, "username", ""))
            owner == subject
          }

          is_admin {
            identity.realm_access.roles[_] == "admin"
          }`,
					},
				},
				{
					JWTClaimSet: &v1beta1.Authorization_JWTClaimSet{
						Match: &v1beta1.Authorization_JWTClaimSet_Match{
							Http: &v1beta1.Authorization_JWTClaimSet_HTTPMatch{
								Path: "/api/*",
							},
						},
						Claim: &v1beta1.Authorization_JWTClaimSet_Claim{
							Aud: "api",
						},
					}},
			},
		},
		Status: v1beta1.ServiceStatus{
			Ready: false,
		},
	}

	secret = v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: "authorino",
		},
		Data: map[string][]byte{
			"clientID":     []byte("clientID"),
			"clientSecret": []byte("clientSecret"),
		},
	}
)

func setupEnvironment(t *testing.T) ServiceReconciler {
	scheme := runtime.NewScheme()
	v1beta1.AddToScheme(scheme)
	v1.AddToScheme(scheme)
	// Create a fake client with a service and a secret.
	client := fake.NewFakeClientWithScheme(scheme, &service, &secret)

	c := cache.NewCache()

	return ServiceReconciler{
		Client: client,
		Log:    ctrl.Log.WithName("reconcilerTest"),
		Scheme: nil,
		Cache:  &c,
	}

}

func TestReconcilerOk(t *testing.T) {

	r := setupEnvironment(t)

	result, err := r.Reconcile(controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: service.Namespace,
			Name:      service.Name,
		},
	})

	if err != nil {
		t.Error(err)
	}

	serviceCheck := v1beta1.Service{}

	r.Client.Get(context.TODO(), client.ObjectKey{
		Namespace: service.Namespace,
		Name:      service.Name,
	}, &serviceCheck)

	assert.Check(t, serviceCheck.Status.Ready)
	// Result should be empty
	assert.DeepEqual(t, result, ctrl.Result{})
}

func TestReconcilerMissingSecret(t *testing.T) {

	r := setupEnvironment(t)

	r.Client.Delete(context.TODO(), &secret)

	result, err := r.Reconcile(controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: service.Namespace,
			Name:      service.Name,
		},
	})

	// Error should be "secret" not found.
	assert.Check(t, errors.IsNotFound(err))
	// Result should be empty
	assert.DeepEqual(t, result, ctrl.Result{})
}

func TestReconcilerNotFound(t *testing.T) {

	r := setupEnvironment(t)

	// Let's try to reconcile a non existing object.
	result, err := r.Reconcile(controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: service.Namespace,
			Name:      "nonExistant",
		},
	})

	if err != nil {
		t.Error(err)
	}

	serviceCheck := v1beta1.Service{}
	r.Client.Get(context.TODO(), client.ObjectKey{
		Namespace: service.Namespace,
		Name:      service.Name,
	}, &serviceCheck)

	// The object we created should remain not ready
	assert.Check(t, !serviceCheck.Status.Ready)

	// Result should be empty
	assert.DeepEqual(t, result, ctrl.Result{})
}

func TestTranslateService(t *testing.T) {

}
