/*
Copyright 2020 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"
	"fmt"

	configv1beta1 "github.com/3scale-labs/authorino/api/v1beta1"
	"github.com/3scale-labs/authorino/pkg/cache"
	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"
	"github.com/3scale-labs/authorino/pkg/config"
	authorinoService "github.com/3scale-labs/authorino/pkg/config"
	authorinoAuthorization "github.com/3scale-labs/authorino/pkg/config/authorization"
	authorinoIdentity "github.com/3scale-labs/authorino/pkg/config/identity"
	authorinoMetadata "github.com/3scale-labs/authorino/pkg/config/metadata"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Cache  *cache.Cache
}

// +kubebuilder:rbac:groups=config.authorino.3scale.net,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=config.authorino.3scale.net,resources=services/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;

func (r *ServiceReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("service", req.NamespacedName)

	service := configv1beta1.Service{}
	err := r.Get(ctx, req.NamespacedName, &service)
	if err != nil && errors.IsNotFound(err) {

		// As we can't get the object, that means it was deleted.
		// Delete all the services related to this k8s object.
		log.Info("object has been deleted, deleted related configs", "object", req)

		//Cleanup all the hosts related to this CRD object.
		r.Cache.Delete(req.String())

		return ctrl.Result{}, nil

	} else if err != nil {
		return ctrl.Result{}, err
	}

	// The object exists so we need to either create it or update
	config, err := r.translateService(ctx, &service)
	if err != nil {
		return ctrl.Result{}, err
	}

	for serviceHost, apiConfig := range config {
		err := r.Cache.Set(req.String(), serviceHost, apiConfig, true)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// TODO: This is not enough. Fix the whole Readiness.
	service.Status.Ready = true
	err = r.Client.Update(ctx, &service)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) translateService(ctx context.Context,
	service *configv1beta1.Service) (map[string]authorinoService.APIConfig, error) {

	identityConfigs := make([]config.IdentityConfig, 0)
	interfacedIdentityConfigs := make([]common.AuthConfigEvaluator, 0)

	for _, identity := range service.Spec.Identity {
		translatedIdentity := &config.IdentityConfig{
			Name: identity.Name,
		}

		authCred := &auth_credentials.AuthCredential{
			KeySelector: identity.Credentials.KeySelector,
			In:          identity.Credentials.In,
		} // TODO: prepare for when missing credentials field

		switch identity.GetType() {
		// oidc
		case configv1beta1.IdentityOidc:
			if oidcConfig, err := authorinoIdentity.NewOIDC(identity.Oidc.Endpoint, authCred); err != nil {
				return nil, err
			} else {
				translatedIdentity.OIDC = oidcConfig
			}

		// api_key
		case configv1beta1.IdentityApiKey:
			translatedIdentity.APIKey = authorinoIdentity.NewApiKeyIdentity(identity.Name, identity.APIKey.LabelSelectors, authCred, r.Client)

		case configv1beta1.TypeUnknown:
			return nil, fmt.Errorf("unknown identity type %v", identity)
		}

		identityConfigs = append(identityConfigs, *translatedIdentity)
		interfacedIdentityConfigs = append(interfacedIdentityConfigs, translatedIdentity)
	}

	interfacedMetadataConfigs := make([]common.AuthConfigEvaluator, 0)

	for _, metadata := range service.Spec.Metadata {
		translatedMetadata := &config.MetadataConfig{
			Name: metadata.Name,
		}

		switch metadata.GetType() {
		// uma
		case configv1beta1.MetadataUma:
			translatedMetadata.UMA = &authorinoMetadata.UMA{}

			// TODO: validate the object on creating to make sure the secret exist? or just retry?
			if metadata.UMA.Credentials != nil {
				secret := &v1.Secret{}
				if err := r.Client.Get(ctx, types.NamespacedName{
					Namespace: service.Namespace,
					Name:      metadata.UMA.Credentials.Name},
					secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				}

				translatedMetadata.UMA.ClientID = string(secret.Data["clientID"])
				translatedMetadata.UMA.ClientSecret = string(secret.Data["clientSecret"])
			}
			// Find the actual name for the Identity Source and use that information for the translated object.
			if idConfig, err := findIdentityConfigByName(identityConfigs, metadata.UMA.IdentitySource); err != nil {
				return nil, err
			} else {
				translatedMetadata.UMA.Endpoint = idConfig.OIDC.Endpoint
			}

		// user_info
		case configv1beta1.MetadataUserinfo:
			translatedMetadata.UserInfo = &authorinoMetadata.UserInfo{}

			if idConfig, err := findIdentityConfigByName(identityConfigs, metadata.UserInfo.IdentitySource); err != nil {
				return nil, err
			} else {
				translatedMetadata.UserInfo.OIDC = idConfig.OIDC
			}

		case configv1beta1.TypeUnknown:
			return nil, fmt.Errorf("unknown identity type %v", metadata)
		}

		interfacedMetadataConfigs = append(interfacedMetadataConfigs, translatedMetadata)
	}

	interfacedAuthorizationConfigs := make([]common.AuthConfigEvaluator, 0)

	for index, authorization := range service.Spec.Authorization {
		translatedAuthorization := &config.AuthorizationConfig{
			Name: authorization.Name,
		}

		switch authorization.GetType() {
		// opa
		case configv1beta1.AuthorizationOPA:
			policyName := service.GetNamespace() + "/" + service.GetName() + "/" + authorization.Name
			translatedAuthorization.OPA = authorinoAuthorization.NewOPAAuthorization(policyName, authorization.OPA.InlineRego, index)

		// jwt
		case configv1beta1.AuthorizationJWTClaimSet:
			// TODO: Ugly, revisit and fix this.
			match := make(map[string]interface{})
			matchByte, _ := json.Marshal(authorization.JWTClaimSet.Claim)
			//TODO: Handle this error properly
			err := json.Unmarshal(matchByte, &match)
			if err != nil {
				panic(err)
			}
			claims := make(map[string]interface{})

			claimsByte, _ := json.Marshal(authorization.JWTClaimSet.Claim)
			//TODO: Handle this error properly
			err = json.Unmarshal(claimsByte, &claims)
			if err != nil {
				panic(err)
			}

			translatedAuthorization.JWT = &authorinoAuthorization.JWTClaims{
				// TODO: Try to map the CRD to this or the other way around.
				Match:  match,
				Claims: claims,
			}

		case configv1beta1.TypeUnknown:
			return nil, fmt.Errorf("unknown identity type %v", authorization)
		}

		interfacedAuthorizationConfigs = append(interfacedAuthorizationConfigs, translatedAuthorization)
	}

	config := make(map[string]authorinoService.APIConfig)

	authorinoService := authorinoService.APIConfig{
		IdentityConfigs:      interfacedIdentityConfigs,
		MetadataConfigs:      interfacedMetadataConfigs,
		AuthorizationConfigs: interfacedAuthorizationConfigs,
	}

	for _, host := range service.Spec.Hosts {
		config[host] = authorinoService
	}
	return config, nil
}

func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.Service{}).
		Complete(r)
}

func findIdentityConfigByName(identityConfigs []config.IdentityConfig, name string) (*config.IdentityConfig, error) {
	for _, id := range identityConfigs {
		if id.Name == name {
			return &id, nil
		}
	}
	return nil, fmt.Errorf("missing identity config %v", name)
}
