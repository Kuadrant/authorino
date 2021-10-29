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
	"fmt"
	"strings"

	configv1beta1 "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config"
	authorinoService "github.com/kuadrant/authorino/pkg/config"
	authorinoAuthorization "github.com/kuadrant/authorino/pkg/config/authorization"
	authorinoIdentity "github.com/kuadrant/authorino/pkg/config/identity"
	authorinoMetadata "github.com/kuadrant/authorino/pkg/config/metadata"
	authorinoResponse "github.com/kuadrant/authorino/pkg/config/response"

	"github.com/go-logr/logr"
	"gopkg.in/square/go-jose.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AuthConfigReconciler reconciles an AuthConfig object
type AuthConfigReconciler struct {
	client.Client
	Logger        logr.Logger
	Scheme        *runtime.Scheme
	Cache         cache.Cache
	LabelSelector labels.Selector
}

// +kubebuilder:rbac:groups=authorino.3scale.net,resources=authconfigs,verbs=get;list;watch;create;update;patch;delete

func (r *AuthConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("authconfig", req.NamespacedName)

	authConfig := configv1beta1.AuthConfig{}
	if err := r.Get(ctx, req.NamespacedName, &authConfig); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found (some error must have happened)
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&authConfig.ObjectMeta, r.LabelSelector) {
		// could not find the resouce: 404 Not found (resouce must have been deleted)
		// or the resource misses required labels (i.e. not to be watched by this controller)
		// delete related authconfigs from cache.
		r.Cache.Delete(req.String())
	} else {
		// resource found and it is to be watched by this controller
		// we need to either create it or update it in the cache
		authConfigByHost, err := r.translateAuthConfig(log.IntoContext(ctx, logger), &authConfig)
		if err != nil {
			return ctrl.Result{}, err
		}

		for host, apiConfig := range authConfigByHost {
			// Check for host collision with another namespace
			if cachedKey, found := r.Cache.FindId(host); found {
				if cachedKeyParts := strings.Split(cachedKey, string(types.Separator)); cachedKeyParts[0] != req.Namespace {
					logger.Info("host already taken in another namespace", "host", host)
					return ctrl.Result{}, nil
				}
			}

			if err := r.Cache.Set(req.String(), host, apiConfig, true); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	logger.Info("resource reconciled")

	return ctrl.Result{}, nil
}

func (r *AuthConfigReconciler) translateAuthConfig(ctx context.Context, authConfig *configv1beta1.AuthConfig) (map[string]authorinoService.APIConfig, error) {
	var ctxWithLogger context.Context

	identityConfigs := make([]config.IdentityConfig, 0)
	interfacedIdentityConfigs := make([]common.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("identity"))

	for _, identity := range authConfig.Spec.Identity {
		extendedProperties := make([]common.JSONProperty, 0)
		for _, property := range identity.ExtendedProperties {
			extendedProperties = append(extendedProperties, common.JSONProperty{
				Name: property.Name,
				Value: common.JSONValue{
					Static:  property.Value,
					Pattern: property.ValueFrom.AuthJSON,
				},
			})
		}

		translatedIdentity := &config.IdentityConfig{
			Name:               identity.Name,
			ExtendedProperties: extendedProperties,
		}

		authCred := auth_credentials.NewAuthCredential(identity.Credentials.KeySelector, string(identity.Credentials.In))

		switch identity.GetType() {
		// oauth2
		case configv1beta1.IdentityOAuth2:
			oauth2Identity := identity.OAuth2

			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      oauth2Identity.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			translatedIdentity.OAuth2 = authorinoIdentity.NewOAuth2Identity(
				oauth2Identity.TokenIntrospectionUrl,
				oauth2Identity.TokenTypeHint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
				authCred,
			)

		// oidc
		case configv1beta1.IdentityOidc:
			translatedIdentity.OIDC = authorinoIdentity.NewOIDC(identity.Oidc.Endpoint, authCred, ctxWithLogger)

		// apiKey
		case configv1beta1.IdentityApiKey:
			translatedIdentity.APIKey = authorinoIdentity.NewApiKeyIdentity(identity.Name, identity.APIKey.LabelSelectors, authCred, r.Client, ctxWithLogger)

		// kubernetes auth
		case configv1beta1.IdentityKubernetesAuth:
			if k8sAuthConfig, err := authorinoIdentity.NewKubernetesAuthIdentity(authCred, identity.KubernetesAuth.Audiences); err != nil {
				return nil, err
			} else {
				translatedIdentity.KubernetesAuth = k8sAuthConfig
			}

		case configv1beta1.TypeUnknown:
			return nil, fmt.Errorf("unknown identity type %v", identity)
		}

		identityConfigs = append(identityConfigs, *translatedIdentity)
		interfacedIdentityConfigs = append(interfacedIdentityConfigs, translatedIdentity)
	}

	interfacedMetadataConfigs := make([]common.AuthConfigEvaluator, 0)

	for _, metadata := range authConfig.Spec.Metadata {
		translatedMetadata := &config.MetadataConfig{
			Name: metadata.Name,
		}

		switch metadata.GetType() {
		// uma
		case configv1beta1.MetadataUma:
			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      metadata.UMA.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			if uma, err := authorinoMetadata.NewUMAMetadata(
				metadata.UMA.Endpoint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
			); err != nil {
				return nil, err
			} else {
				translatedMetadata.UMA = uma
			}

		// user_info
		case configv1beta1.MetadataUserinfo:
			translatedMetadata.UserInfo = &authorinoMetadata.UserInfo{}

			if idConfig, err := findIdentityConfigByName(identityConfigs, metadata.UserInfo.IdentitySource); err != nil {
				return nil, err
			} else {
				translatedMetadata.UserInfo.OIDC = idConfig.OIDC
			}

		// generic http
		case configv1beta1.MetadataGenericHTTP:
			genericHttp := metadata.GenericHTTP
			sharedSecretRef := genericHttp.SharedSecret
			creds := genericHttp.Credentials

			var sharedSecret string
			secret := &v1.Secret{}
			if sharedSecretRef != nil {
				if err := r.Client.Get(ctx, types.NamespacedName{
					Namespace: authConfig.Namespace,
					Name:      sharedSecretRef.Name},
					secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				}
				sharedSecret = string(secret.Data[sharedSecretRef.Key])
			}

			params := make([]common.JSONProperty, 0, len(genericHttp.Parameters))
			for _, param := range genericHttp.Parameters {
				params = append(params, common.JSONProperty{
					Name: param.Name,
					Value: common.JSONValue{
						Static:  param.Value,
						Pattern: param.ValueFrom.AuthJSON,
					},
				})
			}

			translatedMetadata.GenericHTTP = &authorinoMetadata.GenericHttp{
				Endpoint:        genericHttp.Endpoint,
				Method:          string(genericHttp.Method),
				Parameters:      params,
				ContentType:     string(genericHttp.ContentType),
				SharedSecret:    sharedSecret,
				AuthCredentials: auth_credentials.NewAuthCredential(creds.KeySelector, string(creds.In)),
			}

		case configv1beta1.TypeUnknown:
			return nil, fmt.Errorf("unknown metadata type %v", metadata)
		}

		interfacedMetadataConfigs = append(interfacedMetadataConfigs, translatedMetadata)
	}

	interfacedAuthorizationConfigs := make([]common.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("authorization"))

	for index, authorization := range authConfig.Spec.Authorization {
		translatedAuthorization := &config.AuthorizationConfig{
			Name: authorization.Name,
		}

		switch authorization.GetType() {
		// opa
		case configv1beta1.AuthorizationOPA:
			policyName := authConfig.GetNamespace() + "/" + authConfig.GetName() + "/" + authorization.Name
			opa := authorization.OPA
			externalRegistry := opa.ExternalRegistry
			secret := &v1.Secret{}
			var sharedSecret string

			if externalRegistry.SharedSecret != nil {
				if err := r.Client.Get(ctx, types.NamespacedName{
					Namespace: authConfig.Namespace,
					Name:      externalRegistry.SharedSecret.Name},
					secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				}
				sharedSecret = string(secret.Data[externalRegistry.SharedSecret.Key])
			}

			externalSource := authorinoAuthorization.OPAExternalSource{
				Endpoint:        externalRegistry.Endpoint,
				SharedSecret:    sharedSecret,
				AuthCredentials: auth_credentials.NewAuthCredential(externalRegistry.Credentials.KeySelector, string(externalRegistry.Credentials.In)),
			}

			var err error
			translatedAuthorization.OPA, err = authorinoAuthorization.NewOPAAuthorization(policyName, opa.InlineRego, externalSource, index, ctxWithLogger)
			if err != nil {
				return nil, err
			}

		// json
		case configv1beta1.AuthorizationJSONPatternMatching:
			conditions := make([]common.JSONPatternMatchingRule, 0)
			for _, c := range authorization.JSON.Conditions {
				condition := &common.JSONPatternMatchingRule{
					Selector: c.Selector,
					Operator: string(c.Operator),
					Value:    c.Value,
				}
				conditions = append(conditions, *condition)
			}

			rules := make([]common.JSONPatternMatchingRule, 0)
			for _, r := range authorization.JSON.Rules {
				rule := &common.JSONPatternMatchingRule{
					Selector: r.Selector,
					Operator: string(r.Operator),
					Value:    r.Value,
				}
				rules = append(rules, *rule)
			}

			translatedAuthorization.JSON = &authorinoAuthorization.JSONPatternMatching{
				Conditions: conditions,
				Rules:      rules,
			}

		case configv1beta1.AuthorizationKubernetesAuthz:
			conditions := make([]common.JSONPatternMatchingRule, 0)
			for _, c := range authorization.KubernetesAuthz.Conditions {
				condition := &common.JSONPatternMatchingRule{
					Selector: c.Selector,
					Operator: string(c.Operator),
					Value:    c.Value,
				}
				conditions = append(conditions, *condition)
			}

			user := authorization.KubernetesAuthz.User
			authorinoUser := common.JSONValue{Static: user.Value, Pattern: user.ValueFrom.AuthJSON}

			var authorinoResourceAttributes *authorinoAuthorization.KubernetesAuthzResourceAttributes
			resourceAttributes := authorization.KubernetesAuthz.ResourceAttributes
			if resourceAttributes != nil {
				authorinoResourceAttributes = &authorinoAuthorization.KubernetesAuthzResourceAttributes{
					Namespace:   common.JSONValue{Static: resourceAttributes.Namespace.Value, Pattern: resourceAttributes.Namespace.ValueFrom.AuthJSON},
					Group:       common.JSONValue{Static: resourceAttributes.Group.Value, Pattern: resourceAttributes.Group.ValueFrom.AuthJSON},
					Resource:    common.JSONValue{Static: resourceAttributes.Resource.Value, Pattern: resourceAttributes.Resource.ValueFrom.AuthJSON},
					Name:        common.JSONValue{Static: resourceAttributes.Name.Value, Pattern: resourceAttributes.Name.ValueFrom.AuthJSON},
					SubResource: common.JSONValue{Static: resourceAttributes.SubResource.Value, Pattern: resourceAttributes.SubResource.ValueFrom.AuthJSON},
					Verb:        common.JSONValue{Static: resourceAttributes.Verb.Value, Pattern: resourceAttributes.Verb.ValueFrom.AuthJSON},
				}
			}

			var err error
			translatedAuthorization.KubernetesAuthz, err = authorinoAuthorization.NewKubernetesAuthz(conditions, authorinoUser, authorization.KubernetesAuthz.Groups, authorinoResourceAttributes)
			if err != nil {
				return nil, err
			}

		case configv1beta1.TypeUnknown:
			return nil, fmt.Errorf("unknown authorization type %v", authorization)
		}

		interfacedAuthorizationConfigs = append(interfacedAuthorizationConfigs, translatedAuthorization)
	}

	interfacedResponseConfigs := make([]common.AuthConfigEvaluator, 0)

	for _, response := range authConfig.Spec.Response {
		translatedResponse := config.NewResponseConfig(response.Name, string(response.Wrapper), response.WrapperKey)

		switch response.GetType() {
		// wristband
		case configv1beta1.ResponseWristband:
			wristband := response.Wristband
			signingKeys := make([]jose.JSONWebKey, 0)

			for _, signingKeyRef := range wristband.SigningKeyRefs {
				secret := &v1.Secret{}
				secretName := types.NamespacedName{
					Namespace: authConfig.Namespace,
					Name:      signingKeyRef.Name,
				}
				if err := r.Client.Get(ctx, secretName, secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				} else {
					if signingKey, err := authorinoResponse.NewSigningKey(
						signingKeyRef.Name,
						string(signingKeyRef.Algorithm),
						secret.Data["key.pem"],
					); err != nil {
						return nil, err
					} else {
						signingKeys = append(signingKeys, *signingKey)
					}
				}
			}

			customClaims := make([]common.JSONProperty, 0)
			for _, claim := range wristband.CustomClaims {
				customClaims = append(customClaims, common.JSONProperty{
					Name: claim.Name,
					Value: common.JSONValue{
						Static:  claim.Value,
						Pattern: claim.ValueFrom.AuthJSON,
					},
				})
			}

			if authorinoWristband, err := authorinoResponse.NewWristbandConfig(
				wristband.Issuer,
				customClaims,
				wristband.TokenDuration,
				signingKeys,
			); err != nil {
				return nil, err
			} else {
				translatedResponse.Wristband = authorinoWristband
			}

		// dynamic json
		case configv1beta1.ResponseDynamicJSON:
			jsonProperties := make([]common.JSONProperty, 0)

			for _, property := range response.JSON.Properties {
				jsonProperties = append(jsonProperties, common.JSONProperty{
					Name: property.Name,
					Value: common.JSONValue{
						Static:  property.Value,
						Pattern: property.ValueFrom.AuthJSON,
					},
				})
			}

			translatedResponse.DynamicJSON = authorinoResponse.NewDynamicJSONResponse(jsonProperties)

		case configv1beta1.TypeUnknown:
			return nil, fmt.Errorf("unknown response type %v", response)
		}

		interfacedResponseConfigs = append(interfacedResponseConfigs, translatedResponse)
	}

	config := make(map[string]authorinoService.APIConfig)

	apiConfig := authorinoService.APIConfig{
		IdentityConfigs:      interfacedIdentityConfigs,
		MetadataConfigs:      interfacedMetadataConfigs,
		AuthorizationConfigs: interfacedAuthorizationConfigs,
		ResponseConfigs:      interfacedResponseConfigs,
	}

	// denyWith
	if denyWith := authConfig.Spec.DenyWith; denyWith != nil {
		apiConfig.Unauthenticated = buildAuthorinoDenyWithValues(denyWith.Unauthenticated)
		apiConfig.Unauthorized = buildAuthorinoDenyWithValues(denyWith.Unauthorized)
	}

	for _, host := range authConfig.Spec.Hosts {
		config[host] = apiConfig
	}
	return config, nil
}

func (r *AuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.AuthConfig{}, builder.WithPredicates(LabelSelectorPredicate(r.LabelSelector))).
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

func buildAuthorinoDenyWithValues(denyWithSpec *configv1beta1.DenyWithSpec) *authorinoService.DenyWithValues {
	if denyWithSpec == nil {
		return nil
	}

	headers := make([]common.JSONProperty, 0, len(denyWithSpec.Headers))
	for _, header := range denyWithSpec.Headers {
		headers = append(headers, common.JSONProperty{Name: header.Name, Value: common.JSONValue{Static: header.Value, Pattern: header.ValueFrom.AuthJSON}})
	}

	return &authorinoService.DenyWithValues{
		Code:    int32(denyWithSpec.Code),
		Message: denyWithSpec.Message,
		Headers: headers,
	}
}
