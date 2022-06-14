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

	api "github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/evaluators"
	authorization_evaluators "github.com/kuadrant/authorino/pkg/evaluators/authorization"
	identity_evaluators "github.com/kuadrant/authorino/pkg/evaluators/identity"
	metadata_evaluators "github.com/kuadrant/authorino/pkg/evaluators/metadata"
	response_evaluators "github.com/kuadrant/authorino/pkg/evaluators/response"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"

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

const failedToCleanConfig = "failed to clean up all asynchronous workers"

// AuthConfigReconciler reconciles an AuthConfig object
type AuthConfigReconciler struct {
	client.Client
	Logger        logr.Logger
	Scheme        *runtime.Scheme
	Cache         cache.Cache
	LabelSelector labels.Selector
	Namespace     string
}

// +kubebuilder:rbac:groups=authorino.kuadrant.io,resources=authconfigs,verbs=get;list;watch;create;update;patch;delete

func (r *AuthConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("authconfig", req.NamespacedName)
	cacheId := req.String()

	authConfig := api.AuthConfig{}
	if err := r.Get(ctx, req.NamespacedName, &authConfig); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found (some error must have happened)
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&authConfig.ObjectMeta, r.LabelSelector) {
		// could not find the resouce: 404 Not found (resouce must have been deleted)
		// or the resource misses required labels (i.e. not to be watched by this controller)

		// clean all async workers of the config, i.e. shuts down channels and goroutines
		if err := r.cleanConfigs(cacheId, ctx); err != nil {
			logger.Error(err, failedToCleanConfig)
		}

		// delete related authconfigs from cache.
		r.Cache.Delete(cacheId)
	} else {
		// resource found and it is to be watched by this controller
		// we need to either create it or update it in the cache

		// clean all async workers of the config, i.e. shuts down channels and goroutines
		if err := r.cleanConfigs(cacheId, ctx); err != nil {
			logger.Error(err, failedToCleanConfig)
		}

		evaluatorConfigByHost, err := r.translateAuthConfig(log.IntoContext(ctx, logger), &authConfig)
		if err != nil {
			return ctrl.Result{}, err
		}

		for host, evaluatorConfig := range evaluatorConfigByHost {
			// Check for host collision with another namespace
			if cachedKey, found := r.Cache.FindId(host); found {
				if cachedKeyParts := strings.Split(cachedKey, string(types.Separator)); cachedKeyParts[0] != req.Namespace {
					logger.Info("host already taken in another namespace", "host", host)
					return ctrl.Result{}, nil
				}
			}

			if err := r.Cache.Set(cacheId, host, evaluatorConfig, true); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	logger.Info("resource reconciled")

	return ctrl.Result{}, nil
}

func (r *AuthConfigReconciler) cleanConfigs(cacheId string, ctx context.Context) error {
	if hosts := r.Cache.FindKeys(cacheId); len(hosts) > 0 {
		// no need to clean for all the hosts as the config should be the same
		if authConfig := r.Cache.Get(hosts[0]); authConfig != nil {
			return authConfig.Clean(ctx)
		}
	}
	return nil
}

func (r *AuthConfigReconciler) translateAuthConfig(ctx context.Context, authConfig *api.AuthConfig) (map[string]evaluators.AuthConfig, error) {
	var ctxWithLogger context.Context

	identityConfigs := make([]evaluators.IdentityConfig, 0)
	interfacedIdentityConfigs := make([]auth.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("identity"))

	authConfigIdentityConfigs := authConfig.Spec.Identity

	if len(authConfigIdentityConfigs) == 0 {
		authConfigIdentityConfigs = append(authConfigIdentityConfigs, &api.Identity{
			Name:      "anonymous",
			Anonymous: &api.Identity_Anonymous{},
		})
	}

	for _, identity := range authConfigIdentityConfigs {
		extendedProperties := make([]json.JSONProperty, 0)
		for _, property := range identity.ExtendedProperties {
			extendedProperties = append(extendedProperties, json.JSONProperty{
				Name: property.Name,
				Value: json.JSONValue{
					Static:  property.Value,
					Pattern: property.ValueFrom.AuthJSON,
				},
			})
		}

		translatedIdentity := &evaluators.IdentityConfig{
			Name:               identity.Name,
			Priority:           identity.Priority,
			Conditions:         buildJSONPatternExpressions(authConfig, identity.Conditions),
			ExtendedProperties: extendedProperties,
			Metrics:            identity.Metrics,
		}

		if identity.Cache != nil {
			ttl := identity.Cache.TTL
			if ttl == 0 {
				ttl = api.EvaluatorDefaultCacheTTL
			}
			translatedIdentity.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&identity.Cache.Key),
				ttl,
			)
		}

		authCred := auth.NewAuthCredential(identity.Credentials.KeySelector, string(identity.Credentials.In))

		switch identity.GetType() {
		// oauth2
		case api.IdentityOAuth2:
			oauth2Identity := identity.OAuth2

			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      oauth2Identity.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			translatedIdentity.OAuth2 = identity_evaluators.NewOAuth2Identity(
				oauth2Identity.TokenIntrospectionUrl,
				oauth2Identity.TokenTypeHint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
				authCred,
			)

		// oidc
		case api.IdentityOidc:
			translatedIdentity.OIDC = identity_evaluators.NewOIDC(identity.Oidc.Endpoint, authCred, identity.Oidc.TTL, ctxWithLogger)

		// apiKey
		case api.IdentityApiKey:
			namespace := authConfig.Namespace
			if identity.APIKey.AllNamespaces && r.ClusterWide() {
				namespace = ""
			}
			translatedIdentity.APIKey = identity_evaluators.NewApiKeyIdentity(identity.Name, identity.APIKey.LabelSelectors, namespace, authCred, r.Client, ctxWithLogger)

		// kubernetes auth
		case api.IdentityKubernetesAuth:
			if k8sAuthConfig, err := identity_evaluators.NewKubernetesAuthIdentity(authCred, identity.KubernetesAuth.Audiences); err != nil {
				return nil, err
			} else {
				translatedIdentity.KubernetesAuth = k8sAuthConfig
			}

		case api.IdentityPlain:
			translatedIdentity.Plain = &identity_evaluators.Plain{Pattern: identity.Plain.AuthJSON}

		case api.IdentityAnonymous:
			translatedIdentity.Noop = &identity_evaluators.Noop{AuthCredentials: authCred}

		case api.TypeUnknown:
			return nil, fmt.Errorf("unknown identity type %v", identity)
		}

		identityConfigs = append(identityConfigs, *translatedIdentity)
		interfacedIdentityConfigs = append(interfacedIdentityConfigs, translatedIdentity)
	}

	interfacedMetadataConfigs := make([]auth.AuthConfigEvaluator, 0)

	for _, metadata := range authConfig.Spec.Metadata {
		translatedMetadata := &evaluators.MetadataConfig{
			Name:       metadata.Name,
			Priority:   metadata.Priority,
			Conditions: buildJSONPatternExpressions(authConfig, metadata.Conditions),
			Metrics:    metadata.Metrics,
		}

		if metadata.Cache != nil {
			ttl := metadata.Cache.TTL
			if ttl == 0 {
				ttl = api.EvaluatorDefaultCacheTTL
			}
			translatedMetadata.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&metadata.Cache.Key),
				ttl,
			)
		}

		switch metadata.GetType() {
		// uma
		case api.MetadataUma:
			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      metadata.UMA.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			if uma, err := metadata_evaluators.NewUMAMetadata(
				metadata.UMA.Endpoint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
			); err != nil {
				return nil, err
			} else {
				translatedMetadata.UMA = uma
			}

		// user_info
		case api.MetadataUserinfo:
			translatedMetadata.UserInfo = &metadata_evaluators.UserInfo{}

			if idConfig, err := findIdentityConfigByName(identityConfigs, metadata.UserInfo.IdentitySource); err != nil {
				return nil, err
			} else {
				translatedMetadata.UserInfo.OIDC = idConfig.OIDC
			}

		// generic http
		case api.MetadataGenericHTTP:
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

			var body *json.JSONValue
			if b := genericHttp.Body; b != nil {
				body = &json.JSONValue{Static: b.Value, Pattern: b.ValueFrom.AuthJSON}
			}

			params := make([]json.JSONProperty, 0, len(genericHttp.Parameters))
			for _, param := range genericHttp.Parameters {
				params = append(params, json.JSONProperty{
					Name: param.Name,
					Value: json.JSONValue{
						Static:  param.Value,
						Pattern: param.ValueFrom.AuthJSON,
					},
				})
			}

			headers := make([]json.JSONProperty, 0, len(genericHttp.Headers))
			for _, header := range genericHttp.Headers {
				headers = append(headers, json.JSONProperty{
					Name: header.Name,
					Value: json.JSONValue{
						Static:  header.Value,
						Pattern: header.ValueFrom.AuthJSON,
					},
				})
			}

			method := "GET"
			if m := genericHttp.Method; m != nil {
				method = string(*m)
			}

			translatedMetadata.GenericHTTP = &metadata_evaluators.GenericHttp{
				Endpoint:        genericHttp.Endpoint,
				Method:          method,
				Body:            body,
				Parameters:      params,
				Headers:         headers,
				ContentType:     string(genericHttp.ContentType),
				SharedSecret:    sharedSecret,
				AuthCredentials: auth.NewAuthCredential(creds.KeySelector, string(creds.In)),
			}

		case api.TypeUnknown:
			return nil, fmt.Errorf("unknown metadata type %v", metadata)
		}

		interfacedMetadataConfigs = append(interfacedMetadataConfigs, translatedMetadata)
	}

	interfacedAuthorizationConfigs := make([]auth.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("authorization"))

	for index, authorization := range authConfig.Spec.Authorization {
		translatedAuthorization := &evaluators.AuthorizationConfig{
			Name:       authorization.Name,
			Priority:   authorization.Priority,
			Conditions: buildJSONPatternExpressions(authConfig, authorization.Conditions),
			Metrics:    authorization.Metrics,
		}

		if authorization.Cache != nil {
			ttl := authorization.Cache.TTL
			if ttl == 0 {
				ttl = api.EvaluatorDefaultCacheTTL
			}
			translatedAuthorization.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&authorization.Cache.Key),
				ttl,
			)
		}

		switch authorization.GetType() {
		// opa
		case api.AuthorizationOPA:
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

			externalSource := &authorization_evaluators.OPAExternalSource{
				Endpoint:        externalRegistry.Endpoint,
				SharedSecret:    sharedSecret,
				AuthCredentials: auth.NewAuthCredential(externalRegistry.Credentials.KeySelector, string(externalRegistry.Credentials.In)),
				TTL:             externalRegistry.TTL,
			}

			var err error
			translatedAuthorization.OPA, err = authorization_evaluators.NewOPAAuthorization(policyName, opa.InlineRego, externalSource, opa.AllValues, index, ctxWithLogger)
			if err != nil {
				return nil, err
			}

		// json
		case api.AuthorizationJSONPatternMatching:
			translatedAuthorization.JSON = &authorization_evaluators.JSONPatternMatching{
				Rules: buildJSONPatternExpressions(authConfig, authorization.JSON.Rules),
			}

		case api.AuthorizationKubernetesAuthz:
			user := authorization.KubernetesAuthz.User
			authorinoUser := json.JSONValue{Static: user.Value, Pattern: user.ValueFrom.AuthJSON}

			var authorinoResourceAttributes *authorization_evaluators.KubernetesAuthzResourceAttributes
			resourceAttributes := authorization.KubernetesAuthz.ResourceAttributes
			if resourceAttributes != nil {
				authorinoResourceAttributes = &authorization_evaluators.KubernetesAuthzResourceAttributes{
					Namespace:   json.JSONValue{Static: resourceAttributes.Namespace.Value, Pattern: resourceAttributes.Namespace.ValueFrom.AuthJSON},
					Group:       json.JSONValue{Static: resourceAttributes.Group.Value, Pattern: resourceAttributes.Group.ValueFrom.AuthJSON},
					Resource:    json.JSONValue{Static: resourceAttributes.Resource.Value, Pattern: resourceAttributes.Resource.ValueFrom.AuthJSON},
					Name:        json.JSONValue{Static: resourceAttributes.Name.Value, Pattern: resourceAttributes.Name.ValueFrom.AuthJSON},
					SubResource: json.JSONValue{Static: resourceAttributes.SubResource.Value, Pattern: resourceAttributes.SubResource.ValueFrom.AuthJSON},
					Verb:        json.JSONValue{Static: resourceAttributes.Verb.Value, Pattern: resourceAttributes.Verb.ValueFrom.AuthJSON},
				}
			}

			var err error
			translatedAuthorization.KubernetesAuthz, err = authorization_evaluators.NewKubernetesAuthz(authorinoUser, authorization.KubernetesAuthz.Groups, authorinoResourceAttributes)
			if err != nil {
				return nil, err
			}

		case api.TypeUnknown:
			return nil, fmt.Errorf("unknown authorization type %v", authorization)
		}

		interfacedAuthorizationConfigs = append(interfacedAuthorizationConfigs, translatedAuthorization)
	}

	interfacedResponseConfigs := make([]auth.AuthConfigEvaluator, 0)

	for _, response := range authConfig.Spec.Response {
		translatedResponse := evaluators.NewResponseConfig(
			response.Name,
			response.Priority,
			buildJSONPatternExpressions(authConfig, response.Conditions),
			string(response.Wrapper),
			response.WrapperKey,
			response.Metrics,
		)

		if response.Cache != nil {
			ttl := response.Cache.TTL
			if ttl == 0 {
				ttl = api.EvaluatorDefaultCacheTTL
			}
			translatedResponse.Cache = evaluators.NewEvaluatorCache(
				*getJsonFromStaticDynamic(&response.Cache.Key),
				ttl,
			)
		}

		switch response.GetType() {
		// wristband
		case api.ResponseWristband:
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
					if signingKey, err := response_evaluators.NewSigningKey(
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

			customClaims := make([]json.JSONProperty, 0)
			for _, claim := range wristband.CustomClaims {
				customClaims = append(customClaims, json.JSONProperty{
					Name: claim.Name,
					Value: json.JSONValue{
						Static:  claim.Value,
						Pattern: claim.ValueFrom.AuthJSON,
					},
				})
			}

			if authorinoWristband, err := response_evaluators.NewWristbandConfig(
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
		case api.ResponseDynamicJSON:
			jsonProperties := make([]json.JSONProperty, 0)

			for _, property := range response.JSON.Properties {
				jsonProperties = append(jsonProperties, json.JSONProperty{
					Name: property.Name,
					Value: json.JSONValue{
						Static:  property.Value,
						Pattern: property.ValueFrom.AuthJSON,
					},
				})
			}

			translatedResponse.DynamicJSON = response_evaluators.NewDynamicJSONResponse(jsonProperties)

		case api.TypeUnknown:
			return nil, fmt.Errorf("unknown response type %v", response)
		}

		interfacedResponseConfigs = append(interfacedResponseConfigs, translatedResponse)
	}

	evaluatorConfig := evaluators.AuthConfig{
		Conditions:           buildJSONPatternExpressions(authConfig, authConfig.Spec.Conditions),
		IdentityConfigs:      interfacedIdentityConfigs,
		MetadataConfigs:      interfacedMetadataConfigs,
		AuthorizationConfigs: interfacedAuthorizationConfigs,
		ResponseConfigs:      interfacedResponseConfigs,
		Labels:               map[string]string{"namespace": authConfig.Namespace, "name": authConfig.Name},
	}

	// denyWith
	if denyWith := authConfig.Spec.DenyWith; denyWith != nil {
		evaluatorConfig.Unauthenticated = buildAuthorinoDenyWithValues(denyWith.Unauthenticated)
		evaluatorConfig.Unauthorized = buildAuthorinoDenyWithValues(denyWith.Unauthorized)
	}

	evaluatorConfigByHost := make(map[string]evaluators.AuthConfig)
	for _, host := range authConfig.Spec.Hosts {
		evaluatorConfigByHost[host] = evaluatorConfig
	}
	return evaluatorConfigByHost, nil
}

func (r *AuthConfigReconciler) ClusterWide() bool {
	return r.Namespace == ""
}

func (r *AuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.AuthConfig{}, builder.WithPredicates(LabelSelectorPredicate(r.LabelSelector))).
		Complete(r)
}

func findIdentityConfigByName(identityConfigs []evaluators.IdentityConfig, name string) (*evaluators.IdentityConfig, error) {
	for _, id := range identityConfigs {
		if id.Name == name {
			return &id, nil
		}
	}
	return nil, fmt.Errorf("missing identity config %v", name)
}

func buildJSONPatternExpressions(authConfig *api.AuthConfig, patterns []api.JSONPattern) []json.JSONPatternMatchingRule {
	expressions := []json.JSONPatternMatchingRule{}

	for _, pattern := range patterns {
		expressionsToAdd := api.JSONPatternExpressions{}

		if expressionsByRef, found := authConfig.Spec.Patterns[pattern.JSONPatternName]; found {
			expressionsToAdd = append(expressionsToAdd, expressionsByRef...)
		} else {
			expressionsToAdd = append(expressionsToAdd, pattern.JSONPatternExpression)
		}

		for _, expression := range expressionsToAdd {
			expressions = append(expressions, json.JSONPatternMatchingRule{
				Selector: expression.Selector,
				Operator: string(expression.Operator),
				Value:    expression.Value,
			})
		}
	}

	return expressions
}

func buildAuthorinoDenyWithValues(denyWithSpec *api.DenyWithSpec) *evaluators.DenyWithValues {
	if denyWithSpec == nil {
		return nil
	}

	headers := make([]json.JSONProperty, 0, len(denyWithSpec.Headers))
	for _, header := range denyWithSpec.Headers {
		headers = append(headers, json.JSONProperty{Name: header.Name, Value: json.JSONValue{Static: header.Value, Pattern: header.ValueFrom.AuthJSON}})
	}

	return &evaluators.DenyWithValues{
		Code:    int32(denyWithSpec.Code),
		Message: getJsonFromStaticDynamic(denyWithSpec.Message),
		Headers: headers,
		Body:    getJsonFromStaticDynamic(denyWithSpec.Body),
	}
}

func getJsonFromStaticDynamic(value *api.StaticOrDynamicValue) *json.JSONValue {
	if value == nil {
		return nil
	}

	return &json.JSONValue{
		Static:  value.Value,
		Pattern: value.ValueFrom.AuthJSON,
	}
}
