package v1beta2

import (
	"github.com/kuadrant/authorino/api/v1beta1"
	"github.com/kuadrant/authorino/pkg/utils"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

func (src *AuthConfig) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta1.AuthConfig)

	logger := ctrl.Log.WithName("webhook").WithName("authconfig").WithName("converto").WithValues("src", src)
	logger.V(1).Info("starting converting resource")

	// metadata
	dst.ObjectMeta = src.ObjectMeta

	// hosts
	dst.Spec.Hosts = src.Spec.Hosts

	// named patterns
	if src.Spec.NamedPatterns != nil {
		dst.Spec.Patterns = make(map[string]v1beta1.JSONPatternExpressions, len(src.Spec.NamedPatterns))
		for name, patterns := range src.Spec.NamedPatterns {
			dst.Spec.Patterns[name] = utils.Map(patterns, convertPatternExpressionTo)
		}
	}

	// conditions
	dst.Spec.Conditions = utils.Map(src.Spec.Conditions, convertPatternExpressionOrRefTo)

	// identity
	for name, authentication := range src.Spec.Authentication {
		identity := convertAuthenticationTo(name, authentication)
		dst.Spec.Identity = append(dst.Spec.Identity, identity)
	}

	// metadata
	for name, metadataSrc := range src.Spec.Metadata {
		metadata := convertMetadataTo(name, metadataSrc)
		dst.Spec.Metadata = append(dst.Spec.Metadata, metadata)
	}

	// authorization
	for name, authorizationSrc := range src.Spec.Authorization {
		authorization := convertAuthorizationTo(name, authorizationSrc)
		dst.Spec.Authorization = append(dst.Spec.Authorization, authorization)
	}

	// response
	if src.Spec.Response != nil {
		for name, responseSrc := range src.Spec.Response.Success.Headers {
			response := convertSuccessResponseTo(name, responseSrc.SuccessResponseSpec, "httpHeader")
			dst.Spec.Response = append(dst.Spec.Response, response)
		}

		for name, responseSrc := range src.Spec.Response.Success.DynamicMetadata {
			response := convertSuccessResponseTo(name, responseSrc, "envoyDynamicMetadata")
			dst.Spec.Response = append(dst.Spec.Response, response)
		}

		// denyWith
		if src.Spec.Response.Unauthenticated != nil || src.Spec.Response.Unauthorized != nil {
			dst.Spec.DenyWith = &v1beta1.DenyWith{}
		}

		if denyWithSrc := src.Spec.Response.Unauthenticated; denyWithSrc != nil {
			dst.Spec.DenyWith.Unauthenticated = convertDenyWithSpecTo(denyWithSrc)
		}

		if denyWithSrc := src.Spec.Response.Unauthorized; denyWithSrc != nil {
			dst.Spec.DenyWith.Unauthorized = convertDenyWithSpecTo(denyWithSrc)
		}
	}

	// callbacks
	for name, callbackSrc := range src.Spec.Callbacks {
		callback := convertCallbackTo(name, callbackSrc)
		dst.Spec.Callbacks = append(dst.Spec.Callbacks, callback)
	}

	// status
	dst.Status = convertStatusTo(src.Status)

	logger.V(1).Info("finished converting resource", "dst", dst)

	return nil
}

func (dst *AuthConfig) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta1.AuthConfig)

	logger := ctrl.Log.WithName("webhook").WithName("authconfig").WithName("converfrom").WithValues("src", src)
	logger.V(1).Info("starting converting resource")

	// metadata
	dst.ObjectMeta = src.ObjectMeta

	// hosts
	dst.Spec.Hosts = src.Spec.Hosts

	// named patterns
	if src.Spec.Patterns != nil {
		dst.Spec.NamedPatterns = make(map[string]PatternExpressions, len(src.Spec.Patterns))
		for name, patterns := range src.Spec.Patterns {
			dst.Spec.NamedPatterns[name] = utils.Map(patterns, convertPatternExpressionFrom)
		}
	}

	// conditions
	dst.Spec.Conditions = utils.Map(src.Spec.Conditions, convertPatternExpressionOrRefFrom)

	// authentication
	if src.Spec.Identity != nil {
		dst.Spec.Authentication = make(map[string]AuthenticationSpec, len(src.Spec.Identity))
		for _, identity := range src.Spec.Identity {
			name, authentication := convertAuthenticationFrom(identity)
			dst.Spec.Authentication[name] = authentication
		}
	}

	// metadata
	if src.Spec.Metadata != nil {
		dst.Spec.Metadata = make(map[string]MetadataSpec, len(src.Spec.Metadata))
		for _, metadataSrc := range src.Spec.Metadata {
			name, metadata := convertMetadataFrom(metadataSrc)
			dst.Spec.Metadata[name] = metadata
		}
	}

	// authorization
	if src.Spec.Authorization != nil {
		dst.Spec.Authorization = make(map[string]AuthorizationSpec, len(src.Spec.Authorization))
		for _, authorizationSrc := range src.Spec.Authorization {
			name, authorization := convertAuthorizationFrom(authorizationSrc)
			dst.Spec.Authorization[name] = authorization
		}
	}

	// response
	denyWith := src.Spec.DenyWith

	if denyWith != nil || len(src.Spec.Response) > 0 {
		dst.Spec.Response = &ResponseSpec{}
	}

	if denyWith != nil && denyWith.Unauthenticated != nil {
		dst.Spec.Response.Unauthenticated = convertDenyWithSpecFrom(denyWith.Unauthenticated)
	}

	if denyWith != nil && denyWith.Unauthorized != nil {
		dst.Spec.Response.Unauthorized = convertDenyWithSpecFrom(denyWith.Unauthorized)
	}

	for _, responseSrc := range src.Spec.Response {
		if responseSrc.Wrapper != "httpHeader" {
			continue
		}
		if dst.Spec.Response.Success.Headers == nil {
			dst.Spec.Response.Success.Headers = make(map[string]HeaderSuccessResponseSpec)
		}
		name, response := convertSuccessResponseFrom(responseSrc)
		dst.Spec.Response.Success.Headers[name] = HeaderSuccessResponseSpec{
			SuccessResponseSpec: response,
		}
	}

	for _, responseSrc := range src.Spec.Response {
		if responseSrc.Wrapper != "envoyDynamicMetadata" {
			continue
		}
		if dst.Spec.Response.Success.DynamicMetadata == nil {
			dst.Spec.Response.Success.DynamicMetadata = make(map[string]SuccessResponseSpec)
		}
		name, response := convertSuccessResponseFrom(responseSrc)
		dst.Spec.Response.Success.DynamicMetadata[name] = response
	}

	// callbacks
	if src.Spec.Callbacks != nil {
		dst.Spec.Callbacks = make(map[string]CallbackSpec, len(src.Spec.Callbacks))
		for _, callbackSrc := range src.Spec.Callbacks {
			name, callback := convertCallbackFrom(callbackSrc)
			dst.Spec.Callbacks[name] = callback
		}
	}

	// status
	dst.Status = convertStatusFrom(src.Status)

	logger.V(1).Info("finished converting resource", "dst", dst)

	return nil
}

func convertPatternExpressionTo(src PatternExpression) v1beta1.JSONPatternExpression {
	return v1beta1.JSONPatternExpression{
		Selector: src.Selector,
		Operator: v1beta1.JSONPatternOperator(src.Operator),
		Value:    src.Value,
	}
}

func convertPatternExpressionFrom(src v1beta1.JSONPatternExpression) PatternExpression {
	return PatternExpression{
		Selector: src.Selector,
		Operator: PatternExpressionOperator(src.Operator),
		Value:    src.Value,
	}
}

func convertPatternExpressionOrRefTo(src PatternExpressionOrRef) v1beta1.JSONPattern {
	return v1beta1.JSONPattern{
		JSONPatternExpression: convertPatternExpressionTo(src.PatternExpression),
		JSONPatternRef: v1beta1.JSONPatternRef{
			JSONPatternName: src.PatternRef.Name,
		},
	}
}

func convertPatternExpressionOrRefFrom(src v1beta1.JSONPattern) PatternExpressionOrRef {
	return PatternExpressionOrRef{
		PatternExpression: convertPatternExpressionFrom(src.JSONPatternExpression),
		PatternRef: PatternRef{
			Name: src.JSONPatternRef.JSONPatternName,
		},
	}
}

func convertEvaluatorCachingTo(src *EvaluatorCaching) *v1beta1.EvaluatorCaching {
	if src == nil {
		return nil
	}
	return &v1beta1.EvaluatorCaching{
		Key: convertValueOrSelectorTo(src.Key),
		TTL: src.TTL,
	}
}

func convertEvaluatorCachingFrom(src *v1beta1.EvaluatorCaching) *EvaluatorCaching {
	if src == nil {
		return nil
	}
	return &EvaluatorCaching{
		Key: convertValueOrSelectorFrom(src.Key),
		TTL: src.TTL,
	}
}

func convertValueOrSelectorTo(src ValueOrSelector) v1beta1.StaticOrDynamicValue {
	return v1beta1.StaticOrDynamicValue{
		Value:     string(src.Value.Raw),
		ValueFrom: convertSelectorTo(src),
	}
}

func convertValueOrSelectorFrom(src v1beta1.StaticOrDynamicValue) ValueOrSelector {
	value := k8sruntime.RawExtension{}
	if src.ValueFrom.AuthJSON == "" {
		value.Raw = []byte(src.Value)
	}
	return ValueOrSelector{
		Value:    value,
		Selector: src.ValueFrom.AuthJSON,
	}
}

func convertPtrValueOrSelectorTo(src *ValueOrSelector) *v1beta1.StaticOrDynamicValue {
	if src == nil {
		return nil
	}
	v := convertValueOrSelectorTo(*src)
	return &v
}

func convertPtrValueOrSelectorFrom(src *v1beta1.StaticOrDynamicValue) *ValueOrSelector {
	if src == nil {
		return nil
	}
	v := convertValueOrSelectorFrom(*src)
	return &v
}

func convertNamedValuesOrSelectorsTo(src NamedValuesOrSelectors) (jsonProperties []v1beta1.JsonProperty) {
	for name, valueOrSelector := range src {
		jsonProperties = append(jsonProperties, v1beta1.JsonProperty{
			Name:      name,
			Value:     valueOrSelector.Value,
			ValueFrom: convertSelectorTo(valueOrSelector),
		})
	}
	return
}

func convertNamedValuesOrSelectorsFrom(src []v1beta1.JsonProperty) NamedValuesOrSelectors {
	namedValuesOrSelectors := NamedValuesOrSelectors{}
	for _, jsonProperty := range src {
		namedValuesOrSelectors[jsonProperty.Name] = ValueOrSelector{
			Value:    jsonProperty.Value,
			Selector: jsonProperty.ValueFrom.AuthJSON,
		}
	}
	return namedValuesOrSelectors
}

func convertSelectorTo(src ValueOrSelector) v1beta1.ValueFrom {
	return v1beta1.ValueFrom{
		AuthJSON: src.Selector,
	}
}

func convertCredentialsTo(src Credentials) v1beta1.Credentials {
	var in, key string
	switch src.GetType() {
	case AuthorizationHeaderCredentials:
		in = "authorization_header"
		key = src.AuthorizationHeader.Prefix
	case CustomHeaderCredentials:
		in = "custom_header"
		key = src.CustomHeader.Name
	case QueryStringCredentials:
		in = "query"
		key = src.QueryString.Name
	case CookieCredentials:
		in = "cookie"
		key = src.Cookie.Name
	}
	return v1beta1.Credentials{
		In:          v1beta1.Credentials_In(in),
		KeySelector: key,
	}
}

func convertCredentialsFrom(src v1beta1.Credentials) Credentials {
	credentials := Credentials{}
	switch src.In {
	case "authorization_header":
		credentials.AuthorizationHeader = &Prefixed{
			Prefix: src.KeySelector,
		}
	case "custom_header":
		credentials.CustomHeader = &CustomHeader{
			Named: Named{Name: src.KeySelector},
		}
	case "query":
		credentials.QueryString = &Named{
			Name: src.KeySelector,
		}
	case "cookie":
		credentials.Cookie = &Named{
			Name: src.KeySelector,
		}
	}
	return credentials
}

func convertAuthenticationTo(name string, src AuthenticationSpec) *v1beta1.Identity {
	extendedProperties := utils.Map(convertNamedValuesOrSelectorsTo(NamedValuesOrSelectors(src.Overrides)), func(jsonProperty v1beta1.JsonProperty) v1beta1.ExtendedProperty {
		return v1beta1.ExtendedProperty{
			JsonProperty: jsonProperty,
			Overwrite:    true,
		}
	})
	extendedProperties = append(extendedProperties, utils.Map(convertNamedValuesOrSelectorsTo(NamedValuesOrSelectors(src.Defaults)), func(jsonProperty v1beta1.JsonProperty) v1beta1.ExtendedProperty {
		return v1beta1.ExtendedProperty{
			JsonProperty: jsonProperty,
			Overwrite:    false,
		}
	})...)

	identity := &v1beta1.Identity{
		Name:               name,
		Priority:           src.Priority,
		Metrics:            src.Metrics,
		Conditions:         utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
		Cache:              convertEvaluatorCachingTo(src.Cache),
		Credentials:        convertCredentialsTo(src.Credentials),
		ExtendedProperties: extendedProperties,
	}

	switch src.GetMethod() {
	case ApiKeyAuthentication:
		selector := *src.ApiKey.Selector
		identity.APIKey = &v1beta1.Identity_APIKey{
			Selector:      &selector,
			AllNamespaces: src.ApiKey.AllNamespaces,
		}
	case JwtAuthentication:
		identity.Oidc = &v1beta1.Identity_OidcConfig{
			Endpoint: src.Jwt.IssuerUrl,
			TTL:      src.Jwt.TTL,
		}
	case OAuth2TokenIntrospectionAuthentication:
		credentials := *src.OAuth2TokenIntrospection.Credentials
		identity.OAuth2 = &v1beta1.Identity_OAuth2Config{
			TokenIntrospectionUrl: src.OAuth2TokenIntrospection.Url,
			TokenTypeHint:         src.OAuth2TokenIntrospection.TokenTypeHint,
			Credentials:           &credentials,
		}
	case KubernetesTokenReviewAuthentication:
		identity.KubernetesAuth = &v1beta1.Identity_KubernetesAuth{
			Audiences: src.KubernetesTokenReview.Audiences,
		}
	case X509ClientCertificateAuthentication:
		selector := *src.X509ClientCertificate.Selector
		identity.MTLS = &v1beta1.Identity_MTLS{
			Selector:      &selector,
			AllNamespaces: src.X509ClientCertificate.AllNamespaces,
		}
	case PlainIdentityAuthentication:
		selector := v1beta1.Identity_Plain(v1beta1.ValueFrom{
			AuthJSON: src.Plain.Selector,
		})
		identity.Plain = &selector
	case AnonymousAccessAuthentication:
		identity.Anonymous = &v1beta1.Identity_Anonymous{}
	}

	return identity
}

func convertAuthenticationFrom(src *v1beta1.Identity) (string, AuthenticationSpec) {
	var overrides []v1beta1.JsonProperty
	for _, extendedProperty := range src.ExtendedProperties {
		if !extendedProperty.Overwrite {
			continue
		}
		overrides = append(overrides, extendedProperty.JsonProperty)
	}

	var defaults []v1beta1.JsonProperty
	for _, extendedProperty := range src.ExtendedProperties {
		if extendedProperty.Overwrite {
			continue
		}
		defaults = append(defaults, extendedProperty.JsonProperty)
	}

	authentication := AuthenticationSpec{
		CommonEvaluatorSpec: CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
			Cache:      convertEvaluatorCachingFrom(src.Cache),
		},
		Credentials: convertCredentialsFrom(src.Credentials),
		Overrides:   ExtendedProperties(convertNamedValuesOrSelectorsFrom(overrides)),
		Defaults:    ExtendedProperties(convertNamedValuesOrSelectorsFrom(defaults)),
	}

	switch src.GetType() {
	case v1beta1.IdentityApiKey:
		selector := *src.APIKey.Selector
		authentication.ApiKey = &ApiKeyAuthenticationSpec{
			Selector:      &selector,
			AllNamespaces: src.APIKey.AllNamespaces,
		}
	case v1beta1.IdentityOidc:
		authentication.Jwt = &JwtAuthenticationSpec{
			IssuerUrl: src.Oidc.Endpoint,
			TTL:       src.Oidc.TTL,
		}
	case v1beta1.IdentityOAuth2:
		credentials := *src.OAuth2.Credentials
		authentication.OAuth2TokenIntrospection = &OAuth2TokenIntrospectionSpec{
			Url:           src.OAuth2.TokenIntrospectionUrl,
			TokenTypeHint: src.OAuth2.TokenTypeHint,
			Credentials:   &credentials,
		}
	case v1beta1.IdentityKubernetesAuth:
		authentication.KubernetesTokenReview = &KubernetesTokenReviewSpec{
			Audiences: src.KubernetesAuth.Audiences,
		}
	case v1beta1.IdentityMTLS:
		selector := *src.MTLS.Selector
		authentication.X509ClientCertificate = &X509ClientCertificateAuthenticationSpec{
			Selector:      &selector,
			AllNamespaces: src.MTLS.AllNamespaces,
		}
	case v1beta1.IdentityPlain:
		authentication.Plain = &PlainIdentitySpec{
			Selector: src.Plain.AuthJSON,
		}
	case v1beta1.IdentityAnonymous:
		authentication.AnonymousAccess = &AnonymousAccessSpec{}
	}

	return src.Name, authentication
}

func convertMetadataTo(name string, src MetadataSpec) *v1beta1.Metadata {
	metadata := &v1beta1.Metadata{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
		Cache:      convertEvaluatorCachingTo(src.Cache),
	}

	switch src.GetMethod() {
	case HttpMetadata:
		metadata.GenericHTTP = convertHttpEndpointSpecTo(src.Http)
	case UserInfoMetadata:
		metadata.UserInfo = &v1beta1.Metadata_UserInfo{
			IdentitySource: src.UserInfo.IdentitySource,
		}
	case UmaResourceMetadata:
		credentials := *src.Uma.Credentials
		metadata.UMA = &v1beta1.Metadata_UMA{
			Endpoint:    src.Uma.Endpoint,
			Credentials: &credentials,
		}
	}

	return metadata
}

func convertMetadataFrom(src *v1beta1.Metadata) (string, MetadataSpec) {
	metadata := MetadataSpec{
		CommonEvaluatorSpec: CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
			Cache:      convertEvaluatorCachingFrom(src.Cache),
		},
	}

	switch src.GetType() {
	case v1beta1.MetadataGenericHTTP:
		metadata.Http = convertHttpEndpointSpecFrom(src.GenericHTTP)
	case v1beta1.MetadataUserinfo:
		metadata.UserInfo = &UserInfoMetadataSpec{
			IdentitySource: src.UserInfo.IdentitySource,
		}
	case v1beta1.MetadataUma:
		credentials := *src.UMA.Credentials
		metadata.Uma = &UmaMetadataSpec{
			Endpoint:    src.UMA.Endpoint,
			Credentials: &credentials,
		}
	}

	return src.Name, metadata
}

func convertHttpEndpointSpecTo(src *HttpEndpointSpec) *v1beta1.Metadata_GenericHTTP {
	if src == nil {
		return nil
	}
	return &v1beta1.Metadata_GenericHTTP{
		Endpoint:     src.Url,
		Method:       convertMethodTo(src.Method),
		Body:         convertPtrValueOrSelectorTo(src.Body),
		Parameters:   convertNamedValuesOrSelectorsTo(src.Parameters),
		ContentType:  convertContentTypeTo(src.ContentType),
		Headers:      convertNamedValuesOrSelectorsTo(src.Headers),
		SharedSecret: convertSecretKeyReferenceTo(src.SharedSecret),
		OAuth2:       convertOAuth2ClientAuthenticationTo(src.OAuth2),
		Credentials:  convertCredentialsTo(src.Credentials),
	}
}

func convertHttpEndpointSpecFrom(src *v1beta1.Metadata_GenericHTTP) *HttpEndpointSpec {
	if src == nil {
		return nil
	}
	return &HttpEndpointSpec{
		Url:          src.Endpoint,
		Method:       convertMethodFrom(src.Method),
		Body:         convertPtrValueOrSelectorFrom(src.Body),
		Parameters:   convertNamedValuesOrSelectorsFrom(src.Parameters),
		ContentType:  convertContentTypeFrom(src.ContentType),
		Headers:      convertNamedValuesOrSelectorsFrom(src.Headers),
		SharedSecret: convertSecretKeyReferenceFrom(src.SharedSecret),
		OAuth2:       convertOAuth2ClientAuthenticationFrom(src.OAuth2),
		Credentials:  convertCredentialsFrom(src.Credentials),
	}
}

func convertMethodTo(src *HttpMethod) *v1beta1.GenericHTTP_Method {
	if src == nil {
		return nil
	}
	method := v1beta1.GenericHTTP_Method(*src)
	return &method
}

func convertMethodFrom(src *v1beta1.GenericHTTP_Method) *HttpMethod {
	if src == nil {
		return nil
	}
	method := HttpMethod(*src)
	return &method
}

func convertContentTypeTo(src HttpContentType) v1beta1.Metadata_GenericHTTP_ContentType {
	return v1beta1.Metadata_GenericHTTP_ContentType(src)
}

func convertContentTypeFrom(src v1beta1.Metadata_GenericHTTP_ContentType) HttpContentType {
	return HttpContentType(src)
}

func convertOAuth2ClientAuthenticationTo(src *OAuth2ClientAuthentication) *v1beta1.OAuth2ClientAuthentication {
	if src == nil {
		return nil
	}
	o := &v1beta1.OAuth2ClientAuthentication{
		TokenUrl:     src.TokenUrl,
		ClientId:     src.ClientId,
		ClientSecret: *convertSecretKeyReferenceTo(&src.ClientSecret),
		Scopes:       src.Scopes,
		ExtraParams:  src.ExtraParams,
	}
	if src.Cache != nil {
		cache := *src.Cache
		o.Cache = &cache
	}
	return o
}

func convertOAuth2ClientAuthenticationFrom(src *v1beta1.OAuth2ClientAuthentication) *OAuth2ClientAuthentication {
	if src == nil {
		return nil
	}
	o := &OAuth2ClientAuthentication{
		TokenUrl:     src.TokenUrl,
		ClientId:     src.ClientId,
		ClientSecret: *convertSecretKeyReferenceFrom(&src.ClientSecret),
		Scopes:       src.Scopes,
		ExtraParams:  src.ExtraParams,
	}
	if src.Cache != nil {
		cache := *src.Cache
		o.Cache = &cache
	}
	return o
}

func convertSecretKeyReferenceTo(src *SecretKeyReference) *v1beta1.SecretKeyReference {
	if src == nil {
		return nil
	}
	return &v1beta1.SecretKeyReference{
		Name: src.Name,
		Key:  src.Key,
	}
}

func convertSecretKeyReferenceFrom(src *v1beta1.SecretKeyReference) *SecretKeyReference {
	if src == nil {
		return nil
	}
	return &SecretKeyReference{
		Name: src.Name,
		Key:  src.Key,
	}
}

func convertAuthorizationTo(name string, src AuthorizationSpec) *v1beta1.Authorization {
	authorization := &v1beta1.Authorization{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
		Cache:      convertEvaluatorCachingTo(src.Cache),
	}

	switch src.GetMethod() {
	case PatternMatchingAuthorization:
		authorization.JSON = &v1beta1.Authorization_JSONPatternMatching{
			Rules: utils.Map(src.PatternMatching.Patterns, convertPatternExpressionOrRefTo),
		}
	case OpaAuthorization:
		authorization.OPA = &v1beta1.Authorization_OPA{
			InlineRego:       src.Opa.Rego,
			ExternalRegistry: convertOpaExternalRegistryTo(src.Opa.External),
			AllValues:        src.Opa.AllValues,
		}
	case KubernetesSubjectAccessReviewAuthorization:
		authorization.KubernetesAuthz = &v1beta1.Authorization_KubernetesAuthz{
			Groups:             src.KubernetesSubjectAccessReview.Groups,
			ResourceAttributes: convertKubernetesSubjectAccessReviewResourceAttributesTo(src.KubernetesSubjectAccessReview.ResourceAttributes),
		}
		if src.KubernetesSubjectAccessReview.User != nil {
			authorization.KubernetesAuthz.User = convertValueOrSelectorTo(*src.KubernetesSubjectAccessReview.User)
		}
	case SpiceDBAuthorization:
		authorization.Authzed = &v1beta1.Authorization_Authzed{
			Endpoint:     src.SpiceDB.Endpoint,
			Insecure:     src.SpiceDB.Insecure,
			SharedSecret: convertSecretKeyReferenceTo(src.SpiceDB.SharedSecret),
			Subject:      spiceDBObjectTo(src.SpiceDB.Subject),
			Resource:     spiceDBObjectTo(src.SpiceDB.Resource),
			Permission:   convertValueOrSelectorTo(src.SpiceDB.Permission),
		}
	}

	return authorization
}

func convertAuthorizationFrom(src *v1beta1.Authorization) (string, AuthorizationSpec) {
	authorization := AuthorizationSpec{
		CommonEvaluatorSpec: CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
			Cache:      convertEvaluatorCachingFrom(src.Cache),
		},
	}

	switch src.GetType() {
	case v1beta1.AuthorizationJSONPatternMatching:
		authorization.PatternMatching = &PatternMatchingAuthorizationSpec{
			Patterns: utils.Map(src.JSON.Rules, convertPatternExpressionOrRefFrom),
		}
	case v1beta1.AuthorizationOPA:
		authorization.Opa = &OpaAuthorizationSpec{
			Rego:      src.OPA.InlineRego,
			External:  convertOpaExternalRegistryFrom(src.OPA.ExternalRegistry),
			AllValues: src.OPA.AllValues,
		}
	case v1beta1.AuthorizationKubernetesAuthz:
		authorization.KubernetesSubjectAccessReview = &KubernetesSubjectAccessReviewAuthorizationSpec{
			User:               convertPtrValueOrSelectorFrom(&src.KubernetesAuthz.User),
			Groups:             src.KubernetesAuthz.Groups,
			ResourceAttributes: convertKubernetesSubjectAccessReviewResourceAttributesFrom(src.KubernetesAuthz.ResourceAttributes),
		}
	case v1beta1.AuthorizationAuthzed:
		authorization.SpiceDB = &SpiceDBAuthorizationSpec{
			Endpoint:     src.Authzed.Endpoint,
			Insecure:     src.Authzed.Insecure,
			SharedSecret: convertSecretKeyReferenceFrom(src.Authzed.SharedSecret),
			Subject:      spiceDBObjectFrom(src.Authzed.Subject),
			Resource:     spiceDBObjectFrom(src.Authzed.Resource),
			Permission:   convertValueOrSelectorFrom(src.Authzed.Permission),
		}
	}

	return src.Name, authorization
}

func convertOpaExternalRegistryTo(src *ExternalOpaPolicy) v1beta1.ExternalRegistry {
	if src == nil {
		return v1beta1.ExternalRegistry{}
	}
	return v1beta1.ExternalRegistry{
		Endpoint:     src.Url,
		SharedSecret: convertSecretKeyReferenceTo(src.SharedSecret),
		Credentials:  convertCredentialsTo(src.Credentials),
		TTL:          src.TTL,
	}
}

func convertOpaExternalRegistryFrom(src v1beta1.ExternalRegistry) *ExternalOpaPolicy {
	if src.Endpoint == "" {
		return nil
	}
	return &ExternalOpaPolicy{
		HttpEndpointSpec: &HttpEndpointSpec{
			Url:          src.Endpoint,
			SharedSecret: convertSecretKeyReferenceFrom(src.SharedSecret),
			Credentials:  convertCredentialsFrom(src.Credentials),
		},
		TTL: src.TTL,
	}
}

func convertKubernetesSubjectAccessReviewResourceAttributesTo(src *KubernetesSubjectAccessReviewResourceAttributesSpec) *v1beta1.Authorization_KubernetesAuthz_ResourceAttributes {
	if src == nil {
		return nil
	}
	return &v1beta1.Authorization_KubernetesAuthz_ResourceAttributes{
		Namespace:   convertValueOrSelectorTo(src.Namespace),
		Group:       convertValueOrSelectorTo(src.Group),
		Resource:    convertValueOrSelectorTo(src.Resource),
		Name:        convertValueOrSelectorTo(src.Name),
		SubResource: convertValueOrSelectorTo(src.SubResource),
		Verb:        convertValueOrSelectorTo(src.Verb),
	}
}

func convertKubernetesSubjectAccessReviewResourceAttributesFrom(src *v1beta1.Authorization_KubernetesAuthz_ResourceAttributes) *KubernetesSubjectAccessReviewResourceAttributesSpec {
	if src == nil {
		return nil
	}
	return &KubernetesSubjectAccessReviewResourceAttributesSpec{
		Namespace:   convertValueOrSelectorFrom(src.Namespace),
		Group:       convertValueOrSelectorFrom(src.Group),
		Resource:    convertValueOrSelectorFrom(src.Resource),
		Name:        convertValueOrSelectorFrom(src.Name),
		SubResource: convertValueOrSelectorFrom(src.SubResource),
		Verb:        convertValueOrSelectorFrom(src.Verb),
	}
}

func spiceDBObjectTo(src *SpiceDBObject) *v1beta1.AuthzedObject {
	if src == nil {
		return nil
	}
	return &v1beta1.AuthzedObject{
		Kind: convertValueOrSelectorTo(src.Kind),
		Name: convertValueOrSelectorTo(src.Name),
	}
}

func spiceDBObjectFrom(src *v1beta1.AuthzedObject) *SpiceDBObject {
	if src == nil {
		return nil
	}
	return &SpiceDBObject{
		Kind: convertValueOrSelectorFrom(src.Kind),
		Name: convertValueOrSelectorFrom(src.Name),
	}
}

func convertSuccessResponseTo(name string, src SuccessResponseSpec, wrapper string) *v1beta1.Response {
	response := &v1beta1.Response{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
		Cache:      convertEvaluatorCachingTo(src.Cache),
		Wrapper:    v1beta1.Response_Wrapper(wrapper),
		WrapperKey: name,
	}

	switch src.GetMethod() {
	case PlainAuthResponse:
		selector := v1beta1.Response_Plain(convertValueOrSelectorTo(ValueOrSelector(*src.Plain)))
		response.Plain = &selector
	case JsonAuthResponse:
		response.JSON = &v1beta1.Response_DynamicJSON{
			Properties: convertNamedValuesOrSelectorsTo(src.Json.Properties),
		}
	case WristbandAuthResponse:
		response.Wristband = &v1beta1.Response_Wristband{
			Issuer:       src.Wristband.Issuer,
			CustomClaims: convertNamedValuesOrSelectorsTo(src.Wristband.CustomClaims),
		}
		if src.Wristband.TokenDuration != nil {
			duration := *src.Wristband.TokenDuration
			response.Wristband.TokenDuration = &duration
		}
		for _, keySrc := range src.Wristband.SigningKeyRefs {
			if keySrc == nil {
				continue
			}
			key := v1beta1.SigningKeyRef{
				Name:      keySrc.Name,
				Algorithm: v1beta1.SigningKeyAlgorithm(keySrc.Algorithm),
			}
			response.Wristband.SigningKeyRefs = append(response.Wristband.SigningKeyRefs, &key)
		}
	}

	return response
}

func convertSuccessResponseFrom(src *v1beta1.Response) (string, SuccessResponseSpec) {
	response := SuccessResponseSpec{
		CommonEvaluatorSpec: CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
			Cache:      convertEvaluatorCachingFrom(src.Cache),
		},
	}

	switch src.GetType() {
	case v1beta1.ResponsePlain:
		selector := PlainAuthResponseSpec(convertValueOrSelectorFrom(v1beta1.StaticOrDynamicValue(*src.Plain)))
		response.Plain = &selector
	case v1beta1.ResponseDynamicJSON:
		response.Json = &JsonAuthResponseSpec{
			Properties: convertNamedValuesOrSelectorsFrom(src.JSON.Properties),
		}
	case v1beta1.ResponseWristband:
		response.Wristband = &WristbandAuthResponseSpec{
			Issuer:       src.Wristband.Issuer,
			CustomClaims: convertNamedValuesOrSelectorsFrom(src.Wristband.CustomClaims),
		}
		if src.Wristband.TokenDuration != nil {
			duration := *src.Wristband.TokenDuration
			response.Wristband.TokenDuration = &duration
		}
		for _, keySrc := range src.Wristband.SigningKeyRefs {
			if keySrc == nil {
				continue
			}
			key := &WristbandSigningKeyRef{
				Name:      keySrc.Name,
				Algorithm: WristbandSigningKeyAlgorithm(keySrc.Algorithm),
			}
			response.Wristband.SigningKeyRefs = append(response.Wristband.SigningKeyRefs, key)
		}
	}

	return src.Name, response
}

func convertDenyWithSpecTo(src *DenyWithSpec) *v1beta1.DenyWithSpec {
	if src == nil {
		return nil
	}
	return &v1beta1.DenyWithSpec{
		Code:    v1beta1.DenyWith_Code(src.Code),
		Headers: convertNamedValuesOrSelectorsTo(src.Headers),
		Message: convertPtrValueOrSelectorTo(src.Message),
		Body:    convertPtrValueOrSelectorTo(src.Body),
	}
}

func convertDenyWithSpecFrom(src *v1beta1.DenyWithSpec) *DenyWithSpec {
	if src == nil {
		return nil
	}
	return &DenyWithSpec{
		Code:    DenyWithCode(src.Code),
		Headers: convertNamedValuesOrSelectorsFrom(src.Headers),
		Message: convertPtrValueOrSelectorFrom(src.Message),
		Body:    convertPtrValueOrSelectorFrom(src.Body),
	}
}

func convertCallbackTo(name string, src CallbackSpec) *v1beta1.Callback {
	callback := &v1beta1.Callback{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
	}

	switch src.GetMethod() {
	case HttpCallback:
		callback.HTTP = convertHttpEndpointSpecTo(src.Http)
	}

	return callback
}

func convertCallbackFrom(src *v1beta1.Callback) (string, CallbackSpec) {
	callback := CallbackSpec{
		CommonEvaluatorSpec: CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
		},
	}

	switch src.GetType() {
	case v1beta1.CallbackHTTP:
		callback.Http = convertHttpEndpointSpecFrom(src.HTTP)
	}

	return src.Name, callback
}

func convertStatusTo(src AuthConfigStatus) v1beta1.AuthConfigStatus {
	return v1beta1.AuthConfigStatus{
		Conditions: utils.Map(src.Conditions, func(conditionSrc AuthConfigStatusCondition) v1beta1.Condition {
			condition := v1beta1.Condition{
				Type:               v1beta1.ConditionType(conditionSrc.Type),
				Status:             conditionSrc.Status,
				LastTransitionTime: conditionSrc.LastTransitionTime,
				Reason:             conditionSrc.Reason,
				Message:            conditionSrc.Message,
			}
			if conditionSrc.LastUpdatedTime != nil {
				time := *conditionSrc.LastUpdatedTime
				condition.LastUpdatedTime = &time
			}
			return condition
		}),
		Summary: convertStatusSummaryTo(src.Summary),
	}
}

func convertStatusFrom(src v1beta1.AuthConfigStatus) AuthConfigStatus {
	return AuthConfigStatus{
		Conditions: utils.Map(src.Conditions, func(conditionSrc v1beta1.Condition) AuthConfigStatusCondition {
			condition := AuthConfigStatusCondition{
				Type:               StatusConditionType(conditionSrc.Type),
				Status:             conditionSrc.Status,
				LastTransitionTime: conditionSrc.LastTransitionTime,
				Reason:             conditionSrc.Reason,
				Message:            conditionSrc.Message,
			}
			if conditionSrc.LastUpdatedTime != nil {
				time := *conditionSrc.LastUpdatedTime
				condition.LastUpdatedTime = &time
			}
			return condition
		}),
		Summary: convertStatusSummaryFrom(src.Summary),
	}
}

func convertStatusSummaryTo(src AuthConfigStatusSummary) v1beta1.Summary {
	hostsReady := make([]string, len(src.HostsReady))
	copy(hostsReady, src.HostsReady)

	return v1beta1.Summary{
		Ready:                    src.Ready,
		HostsReady:               hostsReady,
		NumHostsReady:            src.NumHostsReady,
		NumIdentitySources:       src.NumIdentitySources,
		NumMetadataSources:       src.NumMetadataSources,
		NumAuthorizationPolicies: src.NumAuthorizationPolicies,
		NumResponseItems:         src.NumResponseItems,
		FestivalWristbandEnabled: src.FestivalWristbandEnabled,
	}
}

func convertStatusSummaryFrom(src v1beta1.Summary) AuthConfigStatusSummary {
	hostsReady := make([]string, len(src.HostsReady))
	copy(hostsReady, src.HostsReady)

	return AuthConfigStatusSummary{
		Ready:                    src.Ready,
		HostsReady:               hostsReady,
		NumHostsReady:            src.NumHostsReady,
		NumIdentitySources:       src.NumIdentitySources,
		NumMetadataSources:       src.NumMetadataSources,
		NumAuthorizationPolicies: src.NumAuthorizationPolicies,
		NumResponseItems:         src.NumResponseItems,
		FestivalWristbandEnabled: src.FestivalWristbandEnabled,
	}
}
