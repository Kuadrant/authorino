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
	"sort"
	"sync"

	api "github.com/kuadrant/authorino/api/v1beta3"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"
	authorization_evaluators "github.com/kuadrant/authorino/pkg/evaluators/authorization"
	identity_evaluators "github.com/kuadrant/authorino/pkg/evaluators/identity"
	metadata_evaluators "github.com/kuadrant/authorino/pkg/evaluators/metadata"
	response_evaluators "github.com/kuadrant/authorino/pkg/evaluators/response"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/kuadrant/authorino/pkg/index"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/oauth2"
	"github.com/kuadrant/authorino/pkg/utils"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	failedToCleanConfig = "failed to clean up all asynchronous workers"

	AuthConfigsReadyzSubpath = "authconfigs"
)

// AuthConfigReconciler reconciles an AuthConfig object
type AuthConfigReconciler struct {
	client.Client
	Logger                      logr.Logger
	Scheme                      *runtime.Scheme
	Index                       index.Index
	AllowSupersedingHostSubsets bool
	StatusReport                *StatusReportMap
	LabelSelector               labels.Selector
	Namespace                   string

	indexBootstrap sync.Mutex
}

// +kubebuilder:rbac:groups=authorino.kuadrant.io,resources=authconfigs,verbs=get;list;watch;create;update;patch;delete

func (r *AuthConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if err := r.bootstrapIndex(ctx); err != nil {
		r.Logger.Error(err, "failed to bootstrap the index")
	}

	resourceId := req.String()
	logger := r.Logger.WithValues("authconfig", resourceId)
	reportReconciled := true

	r.StatusReport.Set(resourceId, api.StatusReasonReconciling, "", []string{})

	var linkedHosts, looseHosts []string

	authConfig := api.AuthConfig{}
	if err := r.Get(ctx, req.NamespacedName, &authConfig); err != nil && !errors.IsNotFound(err) {
		// could not get the resource but not because of a 404 Not found (some error must have happened)
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) || !Watched(&authConfig.ObjectMeta, r.LabelSelector) {
		// could not find the resource: 404 Not found (resource must have been deleted)
		// or the resource misses required labels (i.e. not to be watched by this controller)

		// clean all async workers of the config, i.e. shuts down channels and goroutines
		if err := r.cleanConfigs(resourceId, ctx); err != nil {
			logger.Error(err, failedToCleanConfig)
		}

		// delete related authconfigs from the index.
		r.Index.Delete(resourceId)
		r.StatusReport.Clear(resourceId)
		reportReconciled = false
		logger.Info("resource de-indexed")
	} else {
		// resource found and it is to be watched by this controller
		// we need to either create it or update it in the index

		// clean all async workers of the config, i.e. shuts down channels and goroutines
		if err := r.cleanConfigs(resourceId, ctx); err != nil {
			logger.Error(err, failedToCleanConfig)
		}

		translatedAuthConfig, err := r.translateAuthConfig(log.IntoContext(ctx, logger), &authConfig)
		if err != nil {
			r.StatusReport.Set(resourceId, api.StatusReasonInvalidResource, err.Error(), []string{})
			return ctrl.Result{}, err
		}

		// delete unused hosts from the index
		for _, host := range utils.SubtractSlice(r.Index.FindKeys(resourceId), authConfig.Spec.Hosts) {
			r.Index.DeleteKey(resourceId, host)
		}

		linkedHosts, looseHosts, err = r.addToIndex(log.IntoContext(ctx, logger), req.Namespace, resourceId, translatedAuthConfig, authConfig.Spec.Hosts)

		if len(looseHosts) > 0 {
			r.StatusReport.Set(resourceId, api.StatusReasonHostsNotLinked, "one or more hosts are not linked to the resource", linkedHosts)
			reportReconciled = false
		}

		if err != nil {
			r.StatusReport.Set(resourceId, api.StatusReasonCachingError, err.Error(), linkedHosts)
			return ctrl.Result{}, err
		}
	}

	if len(linkedHosts) > 0 {
		logger.Info("resource reconciled")
	}

	if reportReconciled {
		r.StatusReport.Set(resourceId, api.StatusReasonReconciled, "", linkedHosts)
	}

	return ctrl.Result{}, nil
}

func (r *AuthConfigReconciler) cleanConfigs(resourceId string, ctx context.Context) error {
	if hosts := r.Index.FindKeys(resourceId); len(hosts) > 0 {
		// no need to clean for all the hosts as the config should be the same
		if authConfig := r.Index.Get(hosts[0]); authConfig != nil {
			return authConfig.Clean(ctx)
		}
	}
	return nil
}

func (r *AuthConfigReconciler) translateAuthConfig(ctx context.Context, authConfig *api.AuthConfig) (*evaluators.AuthConfig, error) {
	var ctxWithLogger context.Context

	identityConfigs := make([]evaluators.IdentityConfig, 0)
	interfacedIdentityConfigs := make([]auth.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("identity"))

	authConfigIdentityConfigs := authConfig.Spec.Authentication

	if len(authConfigIdentityConfigs) == 0 {
		if authConfigIdentityConfigs == nil {
			authConfigIdentityConfigs = make(map[string]api.AuthenticationSpec)
		}
		authConfigIdentityConfigs["anonymous"] = api.AuthenticationSpec{
			CommonEvaluatorSpec: api.CommonEvaluatorSpec{},
			Credentials:         api.Credentials{},
			AuthenticationMethodSpec: api.AuthenticationMethodSpec{
				AnonymousAccess: &api.AnonymousAccessSpec{},
			},
		}
	}

	for identityCfgName, identity := range authConfigIdentityConfigs {
		extendedProperties := make([]evaluators.IdentityExtension, 0)
		for propertyName, property := range identity.Defaults {
			if value, err := valueFrom(&property); err != nil {
				return nil, err
			} else {
				extendedProperties = append(extendedProperties, evaluators.NewIdentityExtension(propertyName, value, false))
			}
		}
		for propertyName, property := range identity.Overrides {
			if value, err := valueFrom(&property); err != nil {
				return nil, err
			} else {
				extendedProperties = append(extendedProperties, evaluators.NewIdentityExtension(propertyName, value, true))
			}
		}

		predicates, err := buildPredicates(authConfig, identity.Conditions, jsonexp.All)
		if err != nil {
			return nil, err
		}
		translatedIdentity := &evaluators.IdentityConfig{
			Name:               identityCfgName,
			Priority:           identity.Priority,
			Conditions:         predicates,
			ExtendedProperties: extendedProperties,
			Metrics:            identity.Metrics,
		}

		if identity.Cache != nil {
			ttl := identity.Cache.TTL
			if ttl == 0 {
				ttl = api.EvaluatorDefaultCacheTTL
			}
			key, err := getJsonFromStaticDynamic(&identity.Cache.Key)
			if err != nil {
				return nil, err
			}
			translatedIdentity.Cache = evaluators.NewEvaluatorCache(
				key,
				ttl,
			)
		}

		authCred := newAuthCredential(identity.Credentials)

		switch identity.GetMethod() {
		// oauth2
		case api.OAuth2TokenIntrospectionAuthentication:
			oauth2Identity := identity.OAuth2TokenIntrospection

			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      oauth2Identity.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			translatedIdentity.OAuth2 = identity_evaluators.NewOAuth2Identity(
				oauth2Identity.Url,
				oauth2Identity.TokenTypeHint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
				authCred,
			)

		// oidc
		case api.JwtAuthentication:
			translatedIdentity.OIDC = identity_evaluators.NewOIDC(identity.Jwt.IssuerUrl, authCred, identity.Jwt.TTL, ctxWithLogger)

		// apiKey
		case api.ApiKeyAuthentication:
			namespace := authConfig.Namespace
			if identity.ApiKey.AllNamespaces && r.ClusterWide() {
				namespace = ""
			}
			selector, err := metav1.LabelSelectorAsSelector(identity.ApiKey.Selector)
			if err != nil {
				return nil, err
			}
			translatedIdentity.APIKey = identity_evaluators.NewApiKeyIdentity(identityCfgName, selector, namespace, identity.ApiKey.KeySelectors, authCred, r.Client, ctxWithLogger)

		// MTLS
		case api.X509ClientCertificateAuthentication:
			namespace := authConfig.Namespace
			if identity.X509ClientCertificate.AllNamespaces && r.ClusterWide() {
				namespace = ""
			}
			selector, err := metav1.LabelSelectorAsSelector(identity.X509ClientCertificate.Selector)
			if err != nil {
				return nil, err
			}
			translatedIdentity.MTLS = identity_evaluators.NewMTLSIdentity(identityCfgName, selector, namespace, r.Client, ctxWithLogger)

		// kubernetes auth
		case api.KubernetesTokenReviewAuthentication:
			if k8sAuthConfig, err := identity_evaluators.NewKubernetesAuthIdentity(authCred, identity.KubernetesTokenReview.Audiences); err != nil {
				return nil, err
			} else {
				translatedIdentity.KubernetesAuth = k8sAuthConfig
			}

		case api.PlainIdentityAuthentication:
			if identity.Plain.Expression != "" {
				expression, err := cel.NewExpression(string(identity.Plain.Expression))
				if err != nil {
					return nil, err
				}
				translatedIdentity.Plain = &identity_evaluators.Plain{Value: expression, Pattern: string(identity.Plain.Expression)}
			} else {
				translatedIdentity.Plain = &identity_evaluators.Plain{Value: &json.JSONValue{Pattern: identity.Plain.Selector}, Pattern: identity.Plain.Selector}
			}

		case api.AnonymousAccessAuthentication:
			translatedIdentity.Noop = &identity_evaluators.Noop{AuthCredentials: authCred}

		case api.UnknownAuthenticationMethod:
			return nil, fmt.Errorf("unknown identity type %v", identity)
		}

		identityConfigs = append(identityConfigs, *translatedIdentity)
		interfacedIdentityConfigs = append(interfacedIdentityConfigs, translatedIdentity)
	}

	interfacedMetadataConfigs := make([]auth.AuthConfigEvaluator, 0)

	for name, metadata := range authConfig.Spec.Metadata {
		predicates, err := buildPredicates(authConfig, metadata.Conditions, jsonexp.All)
		if err != nil {
			return nil, err
		}
		translatedMetadata := &evaluators.MetadataConfig{
			Name:       name,
			Priority:   metadata.Priority,
			Conditions: predicates,
			Metrics:    metadata.Metrics,
		}

		if metadata.Cache != nil {
			ttl := metadata.Cache.TTL
			if ttl == 0 {
				ttl = api.EvaluatorDefaultCacheTTL
			}
			key, err := getJsonFromStaticDynamic(&metadata.Cache.Key)
			if err != nil {
				return nil, err
			}
			translatedMetadata.Cache = evaluators.NewEvaluatorCache(
				key,
				ttl,
			)
		}

		switch metadata.GetMethod() {
		// uma
		case api.UmaResourceMetadata:
			secret := &v1.Secret{}
			if err := r.Client.Get(ctx, types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      metadata.Uma.Credentials.Name},
				secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}

			if uma, err := metadata_evaluators.NewUMAMetadata(
				metadata.Uma.Endpoint,
				string(secret.Data["clientID"]),
				string(secret.Data["clientSecret"]),
			); err != nil {
				return nil, err
			} else {
				translatedMetadata.UMA = uma
			}

		// user_info
		case api.UserInfoMetadata:
			translatedMetadata.UserInfo = &metadata_evaluators.UserInfo{}

			if idConfig, err := findIdentityConfigByName(identityConfigs, metadata.UserInfo.IdentitySource); err != nil {
				return nil, err
			} else {
				translatedMetadata.UserInfo.OIDC = idConfig.OIDC
			}

		// generic http
		case api.HttpMetadata:
			ev, err := r.buildGenericHttpEvaluator(ctx, metadata.Http, authConfig.Namespace)
			if err != nil {
				return nil, err
			}
			translatedMetadata.GenericHTTP = ev

		case api.UnknownMetadataMethod:
			return nil, fmt.Errorf("unknown metadata type %v", metadata)
		}

		interfacedMetadataConfigs = append(interfacedMetadataConfigs, translatedMetadata)
	}

	interfacedAuthorizationConfigs := make([]auth.AuthConfigEvaluator, 0)
	ctxWithLogger = log.IntoContext(ctx, log.FromContext(ctx).WithName("authorization"))

	authzIndex := 0
	for authzName, authorization := range authConfig.Spec.Authorization {
		predicates, err := buildPredicates(authConfig, authorization.Conditions, jsonexp.All)
		if err != nil {
			return nil, err
		}
		translatedAuthorization := &evaluators.AuthorizationConfig{
			Name:       authzName,
			Priority:   authorization.Priority,
			Conditions: predicates,
			Metrics:    authorization.Metrics,
		}

		if authorization.Cache != nil {
			ttl := authorization.Cache.TTL
			if ttl == 0 {
				ttl = api.EvaluatorDefaultCacheTTL
			}
			key, err := getJsonFromStaticDynamic(&authorization.Cache.Key)
			if err != nil {
				return nil, err
			}
			translatedAuthorization.Cache = evaluators.NewEvaluatorCache(
				key,
				ttl,
			)
		}

		switch authorization.GetMethod() {
		// opa
		case api.OpaAuthorization:
			policyName := authConfig.GetNamespace() + "/" + authConfig.GetName() + "/" + authzName
			opa := authorization.Opa
			secret := &v1.Secret{}

			var (
				sharedSecret   string
				externalSource *authorization_evaluators.OPAExternalSource
			)

			if opa.External != nil {
				externalRegistry := opa.External
				if externalRegistry.SharedSecret != nil {
					if err := r.Client.Get(ctx, types.NamespacedName{
						Namespace: authConfig.Namespace,
						Name:      externalRegistry.SharedSecret.Name},
						secret); err != nil {
						return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
					}
					sharedSecret = string(secret.Data[externalRegistry.SharedSecret.Key])
				}

				externalSource = &authorization_evaluators.OPAExternalSource{
					Endpoint:        externalRegistry.Url,
					SharedSecret:    sharedSecret,
					AuthCredentials: newAuthCredential(externalRegistry.Credentials),
					TTL:             externalRegistry.TTL,
				}
			}

			var err error
			translatedAuthorization.OPA, err = authorization_evaluators.NewOPAAuthorization(policyName, opa.Rego, externalSource, opa.AllValues, authzIndex, ctxWithLogger)
			if err != nil {
				return nil, err
			}

		// json
		case api.PatternMatchingAuthorization:
			rules, err := buildPredicates(authConfig, authorization.PatternMatching.Patterns, jsonexp.All)
			if err != nil {
				return nil, err
			}
			translatedAuthorization.JSON = &authorization_evaluators.JSONPatternMatching{
				Rules: rules,
			}

		case api.KubernetesSubjectAccessReviewAuthorization:
			user := authorization.KubernetesSubjectAccessReview.User
			authorinoUser, err := valueFrom(user)
			if err != nil {
				return nil, err
			}

			var authorinoResourceAttributes *authorization_evaluators.KubernetesAuthzResourceAttributes
			resourceAttributes := authorization.KubernetesSubjectAccessReview.ResourceAttributes
			if resourceAttributes != nil {
				namespace, err := valueFrom(&resourceAttributes.Namespace)
				if err != nil {
					return nil, err
				}
				group, err := valueFrom(&resourceAttributes.Group)
				if err != nil {
					return nil, err
				}
				resource, err := valueFrom(&resourceAttributes.Resource)
				if err != nil {
					return nil, err
				}
				name, err := valueFrom(&resourceAttributes.Name)
				if err != nil {
					return nil, err
				}
				subResource, err := valueFrom(&resourceAttributes.SubResource)
				if err != nil {
					return nil, err
				}
				verb, err := valueFrom(&resourceAttributes.Verb)
				if err != nil {
					return nil, err
				}
				authorinoResourceAttributes = &authorization_evaluators.KubernetesAuthzResourceAttributes{
					Namespace:   namespace,
					Group:       group,
					Resource:    resource,
					Name:        name,
					SubResource: subResource,
					Verb:        verb,
				}
			}

			var authorinoGroups expressions.Value
			// look for authorizationGroups first
			if authorization.KubernetesSubjectAccessReview.AuthorizationGroups != nil {
				authorinoGroups, err = valueFrom(authorization.KubernetesSubjectAccessReview.AuthorizationGroups)
				if err != nil {
					return nil, err
				}
			} else if len(authorization.KubernetesSubjectAccessReview.Groups) > 0 {
				// use deprecated Groups property otherwise
				authorinoGroups = &json.JSONValue{Static: authorization.KubernetesSubjectAccessReview.Groups}
			}
			translatedAuthorization.KubernetesAuthz, err = authorization_evaluators.NewKubernetesAuthz(authorinoUser, authorinoGroups, authorinoResourceAttributes)
			if err != nil {
				return nil, err
			}

		case api.SpiceDBAuthorization:
			authzed := authorization.SpiceDB

			secret := &v1.Secret{}
			var sharedSecret string
			if secretRef := authzed.SharedSecret; secretRef != nil {
				if err := r.Client.Get(ctx, types.NamespacedName{Namespace: authConfig.Namespace, Name: secretRef.Name}, secret); err != nil {
					return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
				}
				sharedSecret = string(secret.Data[secretRef.Key])
			}

			permission, err := getJsonFromStaticDynamic(&authzed.Permission)
			if err != nil {
				return nil, err
			}
			translatedAuthzed := &authorization_evaluators.Authzed{
				Endpoint:     authzed.Endpoint,
				Insecure:     authzed.Insecure,
				SharedSecret: sharedSecret,
				Permission:   permission,
			}
			translatedAuthzed.Subject, translatedAuthzed.SubjectKind, err = spiceDBObjectToJsonValues(authzed.Subject)
			if err != nil {
				return nil, err
			}
			translatedAuthzed.Resource, translatedAuthzed.ResourceKind, err = spiceDBObjectToJsonValues(authzed.Resource)
			if err != nil {
				return nil, err
			}
			translatedAuthorization.Authzed = translatedAuthzed

		case api.UnknownAuthorizationMethod:
			return nil, fmt.Errorf("unknown authorization type %v", authorization)
		}

		interfacedAuthorizationConfigs = append(interfacedAuthorizationConfigs, translatedAuthorization)
		authzIndex++
	}

	interfacedResponseConfigs := make([]auth.AuthConfigEvaluator, 0)

	if responseConfig := authConfig.Spec.Response; responseConfig != nil {
		for responseName, headerSuccessResponse := range responseConfig.Success.Headers {
			predicates, err := buildPredicates(authConfig, headerSuccessResponse.Conditions, jsonexp.All)
			if err != nil {
				return nil, err
			}
			translatedResponse := evaluators.NewResponseConfig(
				responseName,
				headerSuccessResponse.Priority,
				predicates,
				"httpHeader",
				headerSuccessResponse.Key,
				headerSuccessResponse.Metrics,
			)

			injectCache(headerSuccessResponse.Cache, translatedResponse)
			if err := injectResponseConfig(ctx, authConfig, headerSuccessResponse.SuccessResponseSpec, r, translatedResponse); err != nil {
				return nil, err
			}

			interfacedResponseConfigs = append(interfacedResponseConfigs, translatedResponse)
		}

		for responseName, successResponse := range responseConfig.Success.DynamicMetadata {
			predicates, err := buildPredicates(authConfig, successResponse.Conditions, jsonexp.All)
			if err != nil {
				return nil, err
			}
			translatedResponse := evaluators.NewResponseConfig(
				responseName,
				successResponse.Priority,
				predicates,
				"envoyDynamicMetadata",
				successResponse.Key,
				successResponse.Metrics,
			)

			injectCache(successResponse.Cache, translatedResponse)
			if err := injectResponseConfig(ctx, authConfig, successResponse, r, translatedResponse); err != nil {
				return nil, err
			}

			interfacedResponseConfigs = append(interfacedResponseConfigs, translatedResponse)
		}
	}

	interfacedCallbackConfigs := make([]auth.AuthConfigEvaluator, 0)

	for callbackName, callback := range authConfig.Spec.Callbacks {
		predicates, err := buildPredicates(authConfig, callback.Conditions, jsonexp.All)
		if err != nil {
			return nil, err
		}
		translatedCallback := &evaluators.CallbackConfig{
			Name:       callbackName,
			Priority:   callback.Priority,
			Conditions: predicates,
			Metrics:    callback.Metrics,
		}

		switch callback.GetMethod() {
		// http
		case api.HttpCallback:
			ev, err := r.buildGenericHttpEvaluator(ctx, callback.Http, authConfig.Namespace)
			if err != nil {
				return nil, err
			}
			translatedCallback.HTTP = ev

		case api.UnknownCallbackMethod:
			return nil, fmt.Errorf("unknown callback type %v", callback)
		}

		interfacedCallbackConfigs = append(interfacedCallbackConfigs, translatedCallback)
	}

	predicates, err := buildPredicates(authConfig, authConfig.Spec.Conditions, jsonexp.All)
	if err != nil {
		return nil, err
	}
	translatedAuthConfig := &evaluators.AuthConfig{
		Conditions:           predicates,
		IdentityConfigs:      interfacedIdentityConfigs,
		MetadataConfigs:      interfacedMetadataConfigs,
		AuthorizationConfigs: interfacedAuthorizationConfigs,
		ResponseConfigs:      interfacedResponseConfigs,
		CallbackConfigs:      interfacedCallbackConfigs,
		Labels:               map[string]string{"namespace": authConfig.Namespace, "name": authConfig.Name},
	}

	// denyWith
	if responseConfig := authConfig.Spec.Response; responseConfig != nil {
		if denyWith := responseConfig.Unauthenticated; denyWith != nil {
			value, err := buildAuthorinoDenyWithValues(denyWith)
			if err != nil {
				return nil, err
			}
			translatedAuthConfig.Unauthenticated = value
		}
		if denyWith := responseConfig.Unauthorized; denyWith != nil {
			value, err := buildAuthorinoDenyWithValues(denyWith)
			if err != nil {
				return nil, err
			}
			translatedAuthConfig.Unauthorized = value
		}
	}

	return translatedAuthConfig, nil
}

func valueFrom(user *api.ValueOrSelector) (expressions.Value, error) {
	var strValue expressions.Value
	var err error
	if user.Expression != "" {
		if strValue, err = cel.NewExpression(string(user.Expression)); err != nil {
			return nil, err
		}
	} else {
		strValue = &json.JSONValue{Static: user.Value, Pattern: user.Selector}
	}
	return strValue, nil
}

func injectResponseConfig(ctx context.Context, authConfig *api.AuthConfig, successResponse api.SuccessResponseSpec, r *AuthConfigReconciler, translatedResponse *evaluators.ResponseConfig) error {
	switch successResponse.GetMethod() {
	// wristband
	case api.WristbandAuthResponse:
		wristband := successResponse.Wristband
		signingKeys := make([]jose.JSONWebKey, 0)

		for _, signingKeyRef := range wristband.SigningKeyRefs {
			secret := &v1.Secret{}
			secretName := types.NamespacedName{
				Namespace: authConfig.Namespace,
				Name:      signingKeyRef.Name,
			}
			if err := r.Client.Get(ctx, secretName, secret); err != nil {
				return err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			} else {
				if signingKey, err := response_evaluators.NewSigningKey(
					signingKeyRef.Name,
					string(signingKeyRef.Algorithm),
					secret.Data["key.pem"],
				); err != nil {
					return err
				} else {
					signingKeys = append(signingKeys, *signingKey)
				}
			}
		}

		customClaims := make([]json.JSONProperty, 0)
		for claimName, claim := range wristband.CustomClaims {
			if value, err := valueFrom(&claim); err != nil {
				return err
			} else {
				customClaims = append(customClaims, json.JSONProperty{
					Name:  claimName,
					Value: value,
				})
			}
		}

		if authorinoWristband, err := response_evaluators.NewWristbandConfig(
			wristband.Issuer,
			customClaims,
			wristband.TokenDuration,
			signingKeys,
		); err != nil {
			return err
		} else {
			translatedResponse.Wristband = authorinoWristband
		}

	// dynamic json
	case api.JsonAuthResponse:
		jsonProperties := make([]json.JSONProperty, 0)

		for propertyName, property := range successResponse.Json.Properties {
			if value, err := valueFrom(&property); err != nil {
				return err
			} else {
				jsonProperties = append(jsonProperties, json.JSONProperty{
					Name:  propertyName,
					Value: value,
				})

			}
		}

		translatedResponse.DynamicJSON = response_evaluators.NewDynamicJSONResponse(jsonProperties)

	// plain
	case api.PlainAuthResponse:
		if value, err := valueFrom((*api.ValueOrSelector)(successResponse.Plain)); err != nil {
			return err
		} else {
			translatedResponse.Plain = &response_evaluators.Plain{
				Value: value,
			}
		}

	case api.UnknownAuthResponseMethod:
		return fmt.Errorf("unknown successResponse type %v", successResponse)
	}
	return nil
}

func injectCache(cache *api.EvaluatorCaching, translatedResponse *evaluators.ResponseConfig) error {
	if cache != nil {
		ttl := cache.TTL
		if ttl == 0 {
			ttl = api.EvaluatorDefaultCacheTTL
		}
		if key, err := getJsonFromStaticDynamic(&cache.Key); err != nil {
			return err
		} else {
			translatedResponse.Cache = evaluators.NewEvaluatorCache(
				key,
				ttl,
			)
		}
	}
	return nil
}

func (r *AuthConfigReconciler) addToIndex(ctx context.Context, resourceNamespace, resourceId string, authConfig *evaluators.AuthConfig, hosts []string) (linkedHosts, looseHosts []string, err error) {
	logger := log.FromContext(ctx)
	linkedHosts = []string{}
	looseHosts = []string{}

	for _, host := range hosts {
		// check for host name collision between resources
		if r.hostTaken(host, resourceId) {
			looseHosts = append(looseHosts, host)
			logger.Info("host already taken", "host", host)
			continue
		}

		// add to the index
		if err = r.Index.Set(resourceId, host, *authConfig, true); err != nil {
			return
		}

		linkedHosts = append(linkedHosts, host)
	}

	return
}

func (r *AuthConfigReconciler) hostTaken(host, resourceId string) bool {
	indexedResourceId, found := r.Index.FindId(host)
	return found && indexedResourceId != resourceId && !r.supersedeHostSubset(host, indexedResourceId)
}

func (r *AuthConfigReconciler) supersedeHostSubset(host, supersetResourceId string) bool {
	return r.AllowSupersedingHostSubsets && !utils.SliceContains(r.Index.FindKeys(supersetResourceId), host)
}

func (r *AuthConfigReconciler) bootstrapIndex(ctx context.Context) error {
	r.indexBootstrap.Lock()
	defer r.indexBootstrap.Unlock()

	if !r.Index.Empty() {
		return nil
	}

	authConfigList := api.AuthConfigList{}
	listOptions := []client.ListOption{}
	if r.LabelSelector != nil {
		listOptions = append(listOptions, client.MatchingLabelsSelector{Selector: r.LabelSelector})
	}
	if err := r.List(ctx, &authConfigList, listOptions...); err != nil {
		return err
	}

	count := len(authConfigList.Items)
	if count == 0 {
		return nil
	}

	logger := r.Logger.WithName("bootstrap")
	logger.Info("building the index", "count", count)

	sort.Sort(authConfigList.Items)

	ctx = log.IntoContext(ctx, logger)
	denyAll := &evaluators.AuthConfig{
		AuthorizationConfigs: []auth.AuthConfigEvaluator{evaluators.NewDenyAllAuthorization(ctx, "deny-all", "")},
		DenyWith:             evaluators.DenyWith{Unauthorized: &evaluators.DenyWithValues{Code: 503, Message: &json.JSONValue{Static: "Busy"}}},
	}

	for _, authConfig := range authConfigList.Items {
		if len(authConfig.Status.Summary.HostsReady) == 0 { // unfortunately we cannot use arbitrary field selectors for custom resources yet - https://github.com/kubernetes/kubernetes/issues/51046
			continue
		}

		authConfigName := types.NamespacedName{Namespace: authConfig.Namespace, Name: authConfig.Name}
		logger.V(1).Info("building index", "authconfig", authConfigName.String())

		_, _, err := r.addToIndex(
			log.IntoContext(ctx, logger.WithValues("authconfig", authConfigName)),
			authConfig.Namespace,
			authConfigName.String(),
			denyAll,
			authConfig.Spec.Hosts,
		)

		if err != nil {
			return err
		}
	}

	return nil
}

func (r *AuthConfigReconciler) ClusterWide() bool {
	return r.Namespace == ""
}

func (r *AuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.AuthConfig{}, builder.WithPredicates(LabelSelectorPredicate(r.LabelSelector))).
		Complete(r)
}

func (r *AuthConfigReconciler) Ready(includes, _ []string, _ bool) error {
	if !utils.SliceContains(includes, AuthConfigsReadyzSubpath) {
		return nil
	}

	for id, status := range r.StatusReport.ReadAll() {
		switch status.Reason {
		case api.StatusReasonReconciled:
			continue
		default:
			return fmt.Errorf("authconfig is not ready: %s (reason: %s)", id, status.Reason)
		}
	}
	return nil
}

func (r *AuthConfigReconciler) buildGenericHttpEvaluator(ctx context.Context, http *api.HttpEndpointSpec, namespace string) (*metadata_evaluators.GenericHttp, error) {
	var sharedSecret string
	if sharedSecretRef := http.SharedSecret; sharedSecretRef != nil {
		secret := &v1.Secret{}
		if sharedSecretRef != nil {
			if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: sharedSecretRef.Name}, secret); err != nil {
				return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
			}
			sharedSecret = string(secret.Data[sharedSecretRef.Key])
		}
	}

	var oauth2ClientCredentialsConfig *oauth2.ClientCredentials
	oauth2TokenForceFetch := false
	if oauth2Config := http.OAuth2; oauth2Config != nil {
		secret := &v1.Secret{}
		if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: oauth2Config.ClientSecret.Name}, secret); err != nil {
			return nil, err // TODO: Review this error, perhaps we don't need to return an error, just reenqueue.
		}
		clientSecret := string(secret.Data[oauth2Config.ClientSecret.Key])
		oauth2ClientCredentialsConfig = oauth2.NewClientCredentialsConfig(oauth2Config.TokenUrl, oauth2Config.ClientId, clientSecret, oauth2Config.Scopes, oauth2Config.ExtraParams)
		oauth2TokenForceFetch = oauth2Config.Cache != nil && !*oauth2Config.Cache
	}

	var body expressions.Value
	if b := http.Body; b != nil {
		if value, err := valueFrom(b); err != nil {
			return nil, err
		} else {
			body = value
		}
	}

	params := make([]json.JSONProperty, 0, len(http.Parameters))
	for name, param := range http.Parameters {
		if value, err := valueFrom(&param); err != nil {
			return nil, err
		} else {
			params = append(params, json.JSONProperty{
				Name:  name,
				Value: value,
			})
		}
	}

	headers := make([]json.JSONProperty, 0, len(http.Headers))
	for name, header := range http.Headers {
		if value, err := valueFrom(&header); err != nil {
			return nil, err
		} else {
			headers = append(headers, json.JSONProperty{
				Name:  name,
				Value: value,
			})
		}
	}

	method := "GET"
	if m := http.Method; m != nil {
		method = string(*m)
	}

	var dynamicEndpoint expressions.Value
	if http.UrlExpression != "" {
		endpoint, err := cel.NewExpression(string(http.UrlExpression))
		if err != nil {
			return nil, err
		} else {
			dynamicEndpoint = endpoint
		}
	}

	ev := &metadata_evaluators.GenericHttp{
		Endpoint:              http.Url,
		DynamicEndpoint:       dynamicEndpoint,
		Method:                method,
		Body:                  body,
		Parameters:            params,
		Headers:               headers,
		ContentType:           string(http.ContentType),
		SharedSecret:          sharedSecret,
		OAuth2:                oauth2ClientCredentialsConfig,
		OAuth2TokenForceFetch: oauth2TokenForceFetch,
	}

	if sharedSecret != "" || oauth2ClientCredentialsConfig != nil {
		ev.AuthCredentials = newAuthCredential(http.Credentials)
	}

	return ev, nil
}

func newAuthCredential(creds api.Credentials) *auth.AuthCredential {
	var in, key string
	switch creds.GetType() {
	case api.AuthorizationHeaderCredentials:
		in = "authorization_header"
		key = creds.AuthorizationHeader.Prefix
	case api.CustomHeaderCredentials:
		in = "custom_header"
		key = creds.CustomHeader.Name
	case api.QueryStringCredentials:
		in = "query"
		key = creds.QueryString.Name
	case api.CookieCredentials:
		in = "cookie"
		key = creds.Cookie.Name
	}
	return auth.NewAuthCredential(key, in)
}

func findIdentityConfigByName(identityConfigs []evaluators.IdentityConfig, name string) (*evaluators.IdentityConfig, error) {
	for _, id := range identityConfigs {
		if id.Name == name {
			return &id, nil
		}
	}
	return nil, fmt.Errorf("missing identity config %v", name)
}

func buildPredicates(authConfig *api.AuthConfig, patterns []api.PatternExpressionOrRef, op func(...jsonexp.Expression) jsonexp.Expression) (jsonexp.Expression, error) {
	var expression []jsonexp.Expression
	for _, pattern := range patterns {
		// patterns or refs
		expressions, err := buildJSONExpressionPatterns(authConfig, pattern)
		if err != nil {
			return nil, err
		}
		expression = append(expression, expressions...)
		// all
		if len(pattern.All) > 0 {
			p := make([]api.PatternExpressionOrRef, len(pattern.All))
			for i, ptn := range pattern.All {
				p[i] = ptn.PatternExpressionOrRef
			}
			predicates, err := buildPredicates(authConfig, p, jsonexp.All)
			if err != nil {
				return nil, err
			}
			expression = append(expression, predicates)
		}
		// any
		if len(pattern.Any) > 0 {
			p := make([]api.PatternExpressionOrRef, len(pattern.Any))
			for i, ptn := range pattern.Any {
				p[i] = ptn.PatternExpressionOrRef
			}
			predicates, err := buildPredicates(authConfig, p, jsonexp.Any)
			if err != nil {
				return nil, err
			}
			expression = append(expression, predicates)
		}
	}
	return op(expression...), nil
}

func buildJSONExpressionPatterns(authConfig *api.AuthConfig, pattern api.PatternExpressionOrRef) ([]jsonexp.Expression, error) {
	expressionsToAdd := api.PatternExpressions{}
	expressions := make([]jsonexp.Expression, len(expressionsToAdd))
	if expressionsByRef, found := authConfig.Spec.NamedPatterns[pattern.PatternRef.Name]; found {
		expressionsToAdd = append(expressionsToAdd, expressionsByRef...)
	} else if pattern.PatternExpression.Operator != "" {
		expressionsToAdd = append(expressionsToAdd, pattern.PatternExpression)
	} else if pattern.Predicate != "" {
		if predicate, err := cel.NewPredicate(pattern.Predicate); err != nil {
			return nil, err
		} else {
			expressions = append(expressions, predicate)
		}
	}

	for _, expression := range expressionsToAdd {
		expressions = append(expressions, buildJSONExpressionPattern(expression))
	}
	return expressions, nil
}

func buildJSONExpressionPattern(expression api.PatternExpression) jsonexp.Expression {
	return jsonexp.Pattern{
		Selector: expression.Selector,
		Operator: jsonexp.OperatorFromString(string(expression.Operator)),
		Value:    expression.Value,
	}
}

func buildAuthorinoDenyWithValues(denyWithSpec *api.DenyWithSpec) (*evaluators.DenyWithValues, error) {
	if denyWithSpec == nil {
		return nil, nil
	}

	headers := make([]json.JSONProperty, 0, len(denyWithSpec.Headers))
	for name, header := range denyWithSpec.Headers {
		if value, err := valueFrom(&header); err != nil {
			return nil, err
		} else {
			headers = append(headers, json.JSONProperty{Name: name, Value: value})
		}
	}

	message, err := getJsonFromStaticDynamic(denyWithSpec.Message)
	if err != nil {
		return nil, err
	}
	body, err := getJsonFromStaticDynamic(denyWithSpec.Body)
	if err != nil {
		return nil, err
	}
	return &evaluators.DenyWithValues{
		Code:    int32(denyWithSpec.Code),
		Message: message,
		Headers: headers,
		Body:    body,
	}, nil
}

func getJsonFromStaticDynamic(value *api.ValueOrSelector) (expressions.Value, error) {
	if value == nil {
		return nil, nil
	}
	expression := string(value.Expression)
	if expression != "" {
		return cel.NewExpression(expression)
	}

	return &json.JSONValue{
		Static:  value.Value,
		Pattern: value.Selector,
	}, nil
}

func spiceDBObjectToJsonValues(obj *api.SpiceDBObject) (name expressions.Value, kind expressions.Value, err error) {
	if obj == nil {
		return
	}

	nameResolved, err := getJsonFromStaticDynamic(&obj.Name)
	if err != nil {
		return nil, nil, err
	}
	kindResolved, err := getJsonFromStaticDynamic(&obj.Kind)
	if err != nil {
		return nil, nil, err
	}
	return nameResolved, kindResolved, nil
}
