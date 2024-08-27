package v1beta1

import (
	"encoding/json"

	"github.com/kuadrant/authorino/api/v1beta2"
	"github.com/kuadrant/authorino/pkg/utils"
	"github.com/tidwall/gjson"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

func (src *AuthConfig) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta2.AuthConfig)

	logger := ctrl.Log.WithName("webhook").WithName("authconfig").WithName("converto").WithValues("src", src)
	logger.V(1).Info("starting converting resource")

	// metadata
	dst.ObjectMeta = src.ObjectMeta

	// hosts
	dst.Spec.Hosts = src.Spec.Hosts

	// named patterns
	if src.Spec.Patterns != nil {
		dst.Spec.NamedPatterns = make(map[string]v1beta2.PatternExpressions, len(src.Spec.Patterns))
		for name, patterns := range src.Spec.Patterns {
			dst.Spec.NamedPatterns[name] = utils.Map(patterns, convertPatternExpressionTo)
		}
	}

	// conditions
	dst.Spec.Conditions = utils.Map(src.Spec.Conditions, convertPatternExpressionOrRefTo)

	// authentication
	if src.Spec.Identity != nil {
		dst.Spec.Authentication = make(map[string]v1beta2.AuthenticationSpec, len(src.Spec.Identity))
		for _, identity := range src.Spec.Identity {
			name, authentication := convertAuthenticationTo(identity)
			dst.Spec.Authentication[name] = authentication
		}
	}

	// metadata
	if src.Spec.Metadata != nil {
		dst.Spec.Metadata = make(map[string]v1beta2.MetadataSpec, len(src.Spec.Metadata))
		for _, metadataSrc := range src.Spec.Metadata {
			name, metadata := convertMetadataTo(metadataSrc)
			dst.Spec.Metadata[name] = metadata
		}
	}

	// authorization
	if src.Spec.Authorization != nil {
		dst.Spec.Authorization = make(map[string]v1beta2.AuthorizationSpec, len(src.Spec.Authorization))
		for _, authorizationSrc := range src.Spec.Authorization {
			name, authorization := convertAuthorizationTo(authorizationSrc)
			dst.Spec.Authorization[name] = authorization
		}
	}

	// response
	denyWith := src.Spec.DenyWith

	if denyWith != nil || len(src.Spec.Response) > 0 {
		dst.Spec.Response = &v1beta2.ResponseSpec{}
	}

	if denyWith != nil && denyWith.Unauthenticated != nil {
		dst.Spec.Response.Unauthenticated = convertDenyWithSpecTo(denyWith.Unauthenticated)
	}

	if denyWith != nil && denyWith.Unauthorized != nil {
		dst.Spec.Response.Unauthorized = convertDenyWithSpecTo(denyWith.Unauthorized)
	}

	for _, responseSrc := range src.Spec.Response {
		if responseSrc.Wrapper != "httpHeader" && responseSrc.Wrapper != "" {
			continue
		}
		if dst.Spec.Response.Success.Headers == nil {
			dst.Spec.Response.Success.Headers = make(map[string]v1beta2.HeaderSuccessResponseSpec)
		}
		name, response := convertSuccessResponseTo(responseSrc)
		dst.Spec.Response.Success.Headers[name] = v1beta2.HeaderSuccessResponseSpec{
			SuccessResponseSpec: response,
		}
	}

	for _, responseSrc := range src.Spec.Response {
		if responseSrc.Wrapper != "envoyDynamicMetadata" {
			continue
		}
		if dst.Spec.Response.Success.DynamicMetadata == nil {
			dst.Spec.Response.Success.DynamicMetadata = make(map[string]v1beta2.SuccessResponseSpec)
		}
		name, response := convertSuccessResponseTo(responseSrc)
		dst.Spec.Response.Success.DynamicMetadata[name] = response
	}

	// callbacks
	if src.Spec.Callbacks != nil {
		dst.Spec.Callbacks = make(map[string]v1beta2.CallbackSpec, len(src.Spec.Callbacks))
		for _, callbackSrc := range src.Spec.Callbacks {
			name, callback := convertCallbackTo(callbackSrc)
			dst.Spec.Callbacks[name] = callback
		}
	}

	// status
	dst.Status = convertStatusTo(src.Status)

	logger.V(1).Info("finished converting resource", "dst", dst)

	return nil
}

func (dst *AuthConfig) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta2.AuthConfig)

	logger := ctrl.Log.WithName("webhook").WithName("authconfig").WithName("converfrom").WithValues("src", src)
	logger.V(1).Info("starting converting resource")

	// metadata
	dst.ObjectMeta = src.ObjectMeta

	// hosts
	dst.Spec.Hosts = src.Spec.Hosts

	// named patterns
	if src.Spec.NamedPatterns != nil {
		dst.Spec.Patterns = make(map[string]JSONPatternExpressions, len(src.Spec.NamedPatterns))
		for name, patterns := range src.Spec.NamedPatterns {
			dst.Spec.Patterns[name] = utils.Map(patterns, convertPatternExpressionFrom)
		}
	}

	// conditions
	dst.Spec.Conditions = utils.Map(src.Spec.Conditions, convertPatternExpressionOrRefFrom)

	// identity
	for name, authentication := range src.Spec.Authentication {
		identity := convertAuthenticationFrom(name, authentication)
		dst.Spec.Identity = append(dst.Spec.Identity, identity)
	}

	// metadata
	for name, metadataSrc := range src.Spec.Metadata {
		metadata := convertMetadataFrom(name, metadataSrc)
		dst.Spec.Metadata = append(dst.Spec.Metadata, metadata)
	}

	// authorization
	for name, authorizationSrc := range src.Spec.Authorization {
		authorization := convertAuthorizationFrom(name, authorizationSrc)
		dst.Spec.Authorization = append(dst.Spec.Authorization, authorization)
	}

	// response
	if src.Spec.Response != nil {
		for name, responseSrc := range src.Spec.Response.Success.Headers {
			response := convertSuccessResponseFrom(name, responseSrc.SuccessResponseSpec, "httpHeader")
			dst.Spec.Response = append(dst.Spec.Response, response)
		}

		for name, responseSrc := range src.Spec.Response.Success.DynamicMetadata {
			response := convertSuccessResponseFrom(name, responseSrc, "envoyDynamicMetadata")
			dst.Spec.Response = append(dst.Spec.Response, response)
		}

		// denyWith
		if src.Spec.Response.Unauthenticated != nil || src.Spec.Response.Unauthorized != nil {
			dst.Spec.DenyWith = &DenyWith{}
		}

		if denyWithSrc := src.Spec.Response.Unauthenticated; denyWithSrc != nil {
			dst.Spec.DenyWith.Unauthenticated = convertDenyWithSpecFrom(denyWithSrc)
		}

		if denyWithSrc := src.Spec.Response.Unauthorized; denyWithSrc != nil {
			dst.Spec.DenyWith.Unauthorized = convertDenyWithSpecFrom(denyWithSrc)
		}
	}

	// callbacks
	for name, callbackSrc := range src.Spec.Callbacks {
		callback := convertCallbackFrom(name, callbackSrc)
		dst.Spec.Callbacks = append(dst.Spec.Callbacks, callback)
	}

	// status
	dst.Status = convertStatusFrom(src.Status)

	logger.V(1).Info("finished converting resource", "dst", dst)

	return nil
}

func convertPatternExpressionTo(src JSONPatternExpression) v1beta2.PatternExpression {
	return v1beta2.PatternExpression{
		Selector: src.Selector,
		Operator: v1beta2.PatternExpressionOperator(src.Operator),
		Value:    src.Value,
	}
}

func convertPatternExpressionFrom(src v1beta2.PatternExpression) JSONPatternExpression {
	return JSONPatternExpression{
		Selector: src.Selector,
		Operator: JSONPatternOperator(src.Operator),
		Value:    src.Value,
	}
}

func convertPatternExpressionOrRefTo(src JSONPattern) v1beta2.PatternExpressionOrRef {
	pattern := v1beta2.PatternExpressionOrRef{
		PatternExpression: convertPatternExpressionTo(src.JSONPatternExpression),
		PatternRef: v1beta2.PatternRef{
			Name: src.JSONPatternRef.JSONPatternName,
		},
	}
	if len(src.All) > 0 {
		pattern.All = make([]v1beta2.UnstructuredPatternExpressionOrRef, len(src.All))
		for i, p := range src.All {
			pattern.All[i] = v1beta2.UnstructuredPatternExpressionOrRef{PatternExpressionOrRef: convertPatternExpressionOrRefTo(p.JSONPattern)}
		}
	}
	if len(src.Any) > 0 {
		pattern.Any = make([]v1beta2.UnstructuredPatternExpressionOrRef, len(src.Any))
		for i, p := range src.Any {
			pattern.Any[i] = v1beta2.UnstructuredPatternExpressionOrRef{PatternExpressionOrRef: convertPatternExpressionOrRefTo(p.JSONPattern)}
		}
	}
	return pattern
}

func convertPatternExpressionOrRefFrom(src v1beta2.PatternExpressionOrRef) JSONPattern {
	pattern := JSONPattern{
		JSONPatternExpression: convertPatternExpressionFrom(src.PatternExpression),
		JSONPatternRef: JSONPatternRef{
			JSONPatternName: src.PatternRef.Name,
		},
	}
	if len(src.All) > 0 {
		pattern.All = make([]UnstructuredJSONPattern, len(src.All))
		for i, p := range src.All {
			pattern.All[i] = UnstructuredJSONPattern{JSONPattern: convertPatternExpressionOrRefFrom(p.PatternExpressionOrRef)}
		}
	}
	if len(src.Any) > 0 {
		pattern.Any = make([]UnstructuredJSONPattern, len(src.Any))
		for i, p := range src.Any {
			pattern.Any[i] = UnstructuredJSONPattern{JSONPattern: convertPatternExpressionOrRefFrom(p.PatternExpressionOrRef)}
		}
	}
	return pattern
}

func convertAuthenticationTo(src *Identity) (string, v1beta2.AuthenticationSpec) {
	authentication := v1beta2.AuthenticationSpec{
		CommonEvaluatorSpec: v1beta2.CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
			Cache:      convertEvaluatorCachingTo(src.Cache),
		},
		Credentials: convertCredentialsTo(src.Credentials),
	}

	var overrides []JsonProperty
	for _, extendedProperty := range src.ExtendedProperties {
		if !extendedProperty.Overwrite {
			continue
		}
		overrides = append(overrides, extendedProperty.JsonProperty)
	}
	if len(overrides) > 0 {
		authentication.Overrides = v1beta2.ExtendedProperties(convertNamedValuesOrSelectorsTo(overrides))
	}

	var defaults []JsonProperty
	for _, extendedProperty := range src.ExtendedProperties {
		if extendedProperty.Overwrite {
			continue
		}
		defaults = append(defaults, extendedProperty.JsonProperty)
	}
	if len(defaults) > 0 {
		authentication.Defaults = v1beta2.ExtendedProperties(convertNamedValuesOrSelectorsTo(defaults))
	}

	switch src.GetType() {
	case IdentityApiKey:
		selector := *src.APIKey.Selector
		authentication.ApiKey = &v1beta2.ApiKeyAuthenticationSpec{
			Selector:      &selector,
			AllNamespaces: src.APIKey.AllNamespaces,
		}
	case IdentityOidc:
		authentication.Jwt = &v1beta2.JwtAuthenticationSpec{
			IssuerUrl: src.Oidc.Endpoint,
			TTL:       src.Oidc.TTL,
		}
	case IdentityOAuth2:
		credentials := *src.OAuth2.Credentials
		authentication.OAuth2TokenIntrospection = &v1beta2.OAuth2TokenIntrospectionSpec{
			Url:           src.OAuth2.TokenIntrospectionUrl,
			TokenTypeHint: src.OAuth2.TokenTypeHint,
			Credentials:   &credentials,
		}
	case IdentityKubernetesAuth:
		authentication.KubernetesTokenReview = &v1beta2.KubernetesTokenReviewSpec{
			Audiences: src.KubernetesAuth.Audiences,
		}
	case IdentityMTLS:
		selector := *src.MTLS.Selector
		authentication.X509ClientCertificate = &v1beta2.X509ClientCertificateAuthenticationSpec{
			Selector:      &selector,
			AllNamespaces: src.MTLS.AllNamespaces,
		}
	case IdentityPlain:
		authentication.Plain = &v1beta2.PlainIdentitySpec{
			Selector: src.Plain.AuthJSON,
		}
	case IdentityAnonymous:
		authentication.AnonymousAccess = &v1beta2.AnonymousAccessSpec{}
	}

	return src.Name, authentication
}

func convertAuthenticationFrom(name string, src v1beta2.AuthenticationSpec) *Identity {
	extendedProperties := utils.Map(convertNamedValuesOrSelectorsFrom(v1beta2.NamedValuesOrSelectors(src.Overrides)), func(jsonProperty JsonProperty) ExtendedProperty {
		return ExtendedProperty{
			JsonProperty: jsonProperty,
			Overwrite:    true,
		}
	})
	extendedProperties = append(extendedProperties, utils.Map(convertNamedValuesOrSelectorsFrom(v1beta2.NamedValuesOrSelectors(src.Defaults)), func(jsonProperty JsonProperty) ExtendedProperty {
		return ExtendedProperty{
			JsonProperty: jsonProperty,
			Overwrite:    false,
		}
	})...)

	identity := &Identity{
		Name:               name,
		Priority:           src.Priority,
		Metrics:            src.Metrics,
		Conditions:         utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
		Cache:              convertEvaluatorCachingFrom(src.Cache),
		Credentials:        convertCredentialsFrom(src.Credentials),
		ExtendedProperties: extendedProperties,
	}

	switch src.GetMethod() {
	case v1beta2.ApiKeyAuthentication:
		selector := *src.ApiKey.Selector
		identity.APIKey = &Identity_APIKey{
			Selector:      &selector,
			AllNamespaces: src.ApiKey.AllNamespaces,
		}
	case v1beta2.JwtAuthentication:
		identity.Oidc = &Identity_OidcConfig{
			Endpoint: src.Jwt.IssuerUrl,
			TTL:      src.Jwt.TTL,
		}
	case v1beta2.OAuth2TokenIntrospectionAuthentication:
		credentials := *src.OAuth2TokenIntrospection.Credentials
		identity.OAuth2 = &Identity_OAuth2Config{
			TokenIntrospectionUrl: src.OAuth2TokenIntrospection.Url,
			TokenTypeHint:         src.OAuth2TokenIntrospection.TokenTypeHint,
			Credentials:           &credentials,
		}
	case v1beta2.KubernetesTokenReviewAuthentication:
		identity.KubernetesAuth = &Identity_KubernetesAuth{
			Audiences: src.KubernetesTokenReview.Audiences,
		}
	case v1beta2.X509ClientCertificateAuthentication:
		selector := *src.X509ClientCertificate.Selector
		identity.MTLS = &Identity_MTLS{
			Selector:      &selector,
			AllNamespaces: src.X509ClientCertificate.AllNamespaces,
		}
	case v1beta2.PlainIdentityAuthentication:
		selector := Identity_Plain(ValueFrom{
			AuthJSON: src.Plain.Selector,
		})
		identity.Plain = &selector
	case v1beta2.AnonymousAccessAuthentication:
		identity.Anonymous = &Identity_Anonymous{}
	}

	return identity
}

func convertEvaluatorCachingTo(src *EvaluatorCaching) *v1beta2.EvaluatorCaching {
	if src == nil {
		return nil
	}
	return &v1beta2.EvaluatorCaching{
		Key: convertValueOrSelectorTo(src.Key),
		TTL: src.TTL,
	}
}

func convertEvaluatorCachingFrom(src *v1beta2.EvaluatorCaching) *EvaluatorCaching {
	if src == nil {
		return nil
	}
	return &EvaluatorCaching{
		Key: convertValueOrSelectorFrom(src.Key),
		TTL: src.TTL,
	}
}

func convertValueOrSelectorTo(src StaticOrDynamicValue) v1beta2.ValueOrSelector {
	value := k8sruntime.RawExtension{}
	if src.ValueFrom.AuthJSON == "" {
		jsonString, err := json.Marshal(src.Value)
		if err == nil {
			value.Raw = jsonString
		}
	}
	return v1beta2.ValueOrSelector{
		Value:    value,
		Selector: src.ValueFrom.AuthJSON,
	}
}

func convertValueOrSelectorFrom(src v1beta2.ValueOrSelector) StaticOrDynamicValue {
	return StaticOrDynamicValue{
		Value:     gjson.ParseBytes(src.Value.Raw).String(),
		ValueFrom: convertSelectorFrom(src),
	}
}

func convertCredentialsTo(src Credentials) v1beta2.Credentials {
	credentials := v1beta2.Credentials{}
	switch src.In {
	case "authorization_header":
		credentials.AuthorizationHeader = &v1beta2.Prefixed{
			Prefix: src.KeySelector,
		}
	case "custom_header":
		credentials.CustomHeader = &v1beta2.CustomHeader{
			Named: v1beta2.Named{Name: src.KeySelector},
		}
	case "query":
		credentials.QueryString = &v1beta2.Named{
			Name: src.KeySelector,
		}
	case "cookie":
		credentials.Cookie = &v1beta2.Named{
			Name: src.KeySelector,
		}
	}
	return credentials
}

func convertCredentialsFrom(src v1beta2.Credentials) Credentials {
	var in, key string
	switch src.GetType() {
	case v1beta2.AuthorizationHeaderCredentials:
		in = "authorization_header"
		key = src.AuthorizationHeader.Prefix
	case v1beta2.CustomHeaderCredentials:
		in = "custom_header"
		key = src.CustomHeader.Name
	case v1beta2.QueryStringCredentials:
		in = "query"
		key = src.QueryString.Name
	case v1beta2.CookieCredentials:
		in = "cookie"
		key = src.Cookie.Name
	}
	return Credentials{
		In:          Credentials_In(in),
		KeySelector: key,
	}
}

func convertNamedValuesOrSelectorsTo(src []JsonProperty) v1beta2.NamedValuesOrSelectors {
	if src == nil {
		return nil
	}
	namedValuesOrSelectors := v1beta2.NamedValuesOrSelectors{}
	for _, jsonProperty := range src {
		value := k8sruntime.RawExtension{}
		if jsonProperty.ValueFrom.AuthJSON == "" {
			value.Raw = jsonProperty.Value.Raw
		}
		namedValuesOrSelectors[jsonProperty.Name] = v1beta2.ValueOrSelector{
			Value:    value,
			Selector: jsonProperty.ValueFrom.AuthJSON,
		}
	}
	return namedValuesOrSelectors
}

func convertNamedValuesOrSelectorsFrom(src v1beta2.NamedValuesOrSelectors) []JsonProperty {
	if src == nil {
		return nil
	}
	jsonProperties := make([]JsonProperty, 0, len(src))
	for name, valueOrSelector := range src {
		jsonProperties = append(jsonProperties, JsonProperty{
			Name:      name,
			Value:     valueOrSelector.Value,
			ValueFrom: convertSelectorFrom(valueOrSelector),
		})
	}
	return jsonProperties
}

func convertSelectorFrom(src v1beta2.ValueOrSelector) ValueFrom {
	return ValueFrom{
		AuthJSON: src.Selector,
	}
}

func convertMetadataTo(src *Metadata) (string, v1beta2.MetadataSpec) {
	metadata := v1beta2.MetadataSpec{
		CommonEvaluatorSpec: v1beta2.CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
			Cache:      convertEvaluatorCachingTo(src.Cache),
		},
	}

	switch src.GetType() {
	case MetadataGenericHTTP:
		metadata.Http = convertHttpEndpointSpecTo(src.GenericHTTP)
	case MetadataUserinfo:
		metadata.UserInfo = &v1beta2.UserInfoMetadataSpec{
			IdentitySource: src.UserInfo.IdentitySource,
		}
	case MetadataUma:
		credentials := *src.UMA.Credentials
		metadata.Uma = &v1beta2.UmaMetadataSpec{
			Endpoint:    src.UMA.Endpoint,
			Credentials: &credentials,
		}
	}

	return src.Name, metadata
}

func convertMetadataFrom(name string, src v1beta2.MetadataSpec) *Metadata {
	metadata := &Metadata{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
		Cache:      convertEvaluatorCachingFrom(src.Cache),
	}

	switch src.GetMethod() {
	case v1beta2.HttpMetadata:
		metadata.GenericHTTP = convertHttpEndpointSpecFrom(src.Http)
	case v1beta2.UserInfoMetadata:
		metadata.UserInfo = &Metadata_UserInfo{
			IdentitySource: src.UserInfo.IdentitySource,
		}
	case v1beta2.UmaResourceMetadata:
		credentials := *src.Uma.Credentials
		metadata.UMA = &Metadata_UMA{
			Endpoint:    src.Uma.Endpoint,
			Credentials: &credentials,
		}
	}

	return metadata
}

func convertHttpEndpointSpecTo(src *Metadata_GenericHTTP) *v1beta2.HttpEndpointSpec {
	if src == nil {
		return nil
	}
	return &v1beta2.HttpEndpointSpec{
		Url:          src.Endpoint,
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

func convertHttpEndpointSpecFrom(src *v1beta2.HttpEndpointSpec) *Metadata_GenericHTTP {
	if src == nil {
		return nil
	}
	return &Metadata_GenericHTTP{
		Endpoint:     src.Url,
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

func convertMethodTo(src *GenericHTTP_Method) *v1beta2.HttpMethod {
	if src == nil {
		return nil
	}
	method := v1beta2.HttpMethod(*src)
	return &method
}

func convertMethodFrom(src *v1beta2.HttpMethod) *GenericHTTP_Method {
	if src == nil {
		return nil
	}
	method := GenericHTTP_Method(*src)
	return &method
}

func convertPtrValueOrSelectorTo(src *StaticOrDynamicValue) *v1beta2.ValueOrSelector {
	if src == nil {
		return nil
	}
	v := convertValueOrSelectorTo(*src)
	return &v
}

func convertPtrValueOrSelectorFrom(src *v1beta2.ValueOrSelector) *StaticOrDynamicValue {
	if src == nil {
		return nil
	}
	v := convertValueOrSelectorFrom(*src)
	return &v
}

func convertContentTypeTo(src Metadata_GenericHTTP_ContentType) v1beta2.HttpContentType {
	return v1beta2.HttpContentType(src)
}

func convertContentTypeFrom(src v1beta2.HttpContentType) Metadata_GenericHTTP_ContentType {
	return Metadata_GenericHTTP_ContentType(src)
}

func convertSecretKeyReferenceTo(src *SecretKeyReference) *v1beta2.SecretKeyReference {
	if src == nil {
		return nil
	}
	return &v1beta2.SecretKeyReference{
		Name: src.Name,
		Key:  src.Key,
	}
}

func convertSecretKeyReferenceFrom(src *v1beta2.SecretKeyReference) *SecretKeyReference {
	if src == nil {
		return nil
	}
	return &SecretKeyReference{
		Name: src.Name,
		Key:  src.Key,
	}
}

func convertOAuth2ClientAuthenticationTo(src *OAuth2ClientAuthentication) *v1beta2.OAuth2ClientAuthentication {
	if src == nil {
		return nil
	}
	o := &v1beta2.OAuth2ClientAuthentication{
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

func convertOAuth2ClientAuthenticationFrom(src *v1beta2.OAuth2ClientAuthentication) *OAuth2ClientAuthentication {
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

func convertAuthorizationTo(src *Authorization) (string, v1beta2.AuthorizationSpec) {
	authorization := v1beta2.AuthorizationSpec{
		CommonEvaluatorSpec: v1beta2.CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
			Cache:      convertEvaluatorCachingTo(src.Cache),
		},
	}

	switch src.GetType() {
	case AuthorizationJSONPatternMatching:
		authorization.PatternMatching = &v1beta2.PatternMatchingAuthorizationSpec{
			Patterns: utils.Map(src.JSON.Rules, convertPatternExpressionOrRefTo),
		}
	case AuthorizationOPA:
		authorization.Opa = &v1beta2.OpaAuthorizationSpec{
			Rego:      src.OPA.InlineRego,
			External:  convertOpaExternalRegistryTo(src.OPA.ExternalRegistry),
			AllValues: src.OPA.AllValues,
		}
	case AuthorizationKubernetesAuthz:
		authorization.KubernetesSubjectAccessReview = &v1beta2.KubernetesSubjectAccessReviewAuthorizationSpec{
			User:               convertPtrValueOrSelectorTo(&src.KubernetesAuthz.User),
			Groups:             src.KubernetesAuthz.Groups,
			ResourceAttributes: convertKubernetesSubjectAccessReviewResourceAttributesTo(src.KubernetesAuthz.ResourceAttributes),
		}
	case AuthorizationAuthzed:
		authorization.SpiceDB = &v1beta2.SpiceDBAuthorizationSpec{
			Endpoint:     src.Authzed.Endpoint,
			Insecure:     src.Authzed.Insecure,
			SharedSecret: convertSecretKeyReferenceTo(src.Authzed.SharedSecret),
			Subject:      spiceDBObjectTo(src.Authzed.Subject),
			Resource:     spiceDBObjectTo(src.Authzed.Resource),
			Permission:   convertValueOrSelectorTo(src.Authzed.Permission),
		}
	}

	return src.Name, authorization
}

func convertAuthorizationFrom(name string, src v1beta2.AuthorizationSpec) *Authorization {
	authorization := &Authorization{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
		Cache:      convertEvaluatorCachingFrom(src.Cache),
	}

	switch src.GetMethod() {
	case v1beta2.PatternMatchingAuthorization:
		authorization.JSON = &Authorization_JSONPatternMatching{
			Rules: utils.Map(src.PatternMatching.Patterns, convertPatternExpressionOrRefFrom),
		}
	case v1beta2.OpaAuthorization:
		authorization.OPA = &Authorization_OPA{
			InlineRego:       src.Opa.Rego,
			ExternalRegistry: convertOpaExternalRegistryFrom(src.Opa.External),
			AllValues:        src.Opa.AllValues,
		}
	case v1beta2.KubernetesSubjectAccessReviewAuthorization:
		authorization.KubernetesAuthz = &Authorization_KubernetesAuthz{
			Groups:             src.KubernetesSubjectAccessReview.Groups,
			ResourceAttributes: convertKubernetesSubjectAccessReviewResourceAttributesFrom(src.KubernetesSubjectAccessReview.ResourceAttributes),
		}
		if src.KubernetesSubjectAccessReview.User != nil {
			authorization.KubernetesAuthz.User = convertValueOrSelectorFrom(*src.KubernetesSubjectAccessReview.User)
		}
	case v1beta2.SpiceDBAuthorization:
		authorization.Authzed = &Authorization_Authzed{
			Endpoint:     src.SpiceDB.Endpoint,
			Insecure:     src.SpiceDB.Insecure,
			SharedSecret: convertSecretKeyReferenceFrom(src.SpiceDB.SharedSecret),
			Subject:      spiceDBObjectFrom(src.SpiceDB.Subject),
			Resource:     spiceDBObjectFrom(src.SpiceDB.Resource),
			Permission:   convertValueOrSelectorFrom(src.SpiceDB.Permission),
		}
	}

	return authorization
}

func convertOpaExternalRegistryTo(src ExternalRegistry) *v1beta2.ExternalOpaPolicy {
	if src.Endpoint == "" {
		return nil
	}
	return &v1beta2.ExternalOpaPolicy{
		HttpEndpointSpec: &v1beta2.HttpEndpointSpec{
			Url:          src.Endpoint,
			SharedSecret: convertSecretKeyReferenceTo(src.SharedSecret),
			Credentials:  convertCredentialsTo(src.Credentials),
		},
		TTL: src.TTL,
	}
}

func convertOpaExternalRegistryFrom(src *v1beta2.ExternalOpaPolicy) ExternalRegistry {
	if src == nil {
		return ExternalRegistry{}
	}
	return ExternalRegistry{
		Endpoint:     src.Url,
		SharedSecret: convertSecretKeyReferenceFrom(src.SharedSecret),
		Credentials:  convertCredentialsFrom(src.Credentials),
		TTL:          src.TTL,
	}
}

func convertKubernetesSubjectAccessReviewResourceAttributesTo(src *Authorization_KubernetesAuthz_ResourceAttributes) *v1beta2.KubernetesSubjectAccessReviewResourceAttributesSpec {
	if src == nil {
		return nil
	}
	return &v1beta2.KubernetesSubjectAccessReviewResourceAttributesSpec{
		Namespace:   convertValueOrSelectorTo(src.Namespace),
		Group:       convertValueOrSelectorTo(src.Group),
		Resource:    convertValueOrSelectorTo(src.Resource),
		Name:        convertValueOrSelectorTo(src.Name),
		SubResource: convertValueOrSelectorTo(src.SubResource),
		Verb:        convertValueOrSelectorTo(src.Verb),
	}
}

func convertKubernetesSubjectAccessReviewResourceAttributesFrom(src *v1beta2.KubernetesSubjectAccessReviewResourceAttributesSpec) *Authorization_KubernetesAuthz_ResourceAttributes {
	if src == nil {
		return nil
	}
	return &Authorization_KubernetesAuthz_ResourceAttributes{
		Namespace:   convertValueOrSelectorFrom(src.Namespace),
		Group:       convertValueOrSelectorFrom(src.Group),
		Resource:    convertValueOrSelectorFrom(src.Resource),
		Name:        convertValueOrSelectorFrom(src.Name),
		SubResource: convertValueOrSelectorFrom(src.SubResource),
		Verb:        convertValueOrSelectorFrom(src.Verb),
	}
}

func spiceDBObjectTo(src *AuthzedObject) *v1beta2.SpiceDBObject {
	if src == nil {
		return nil
	}
	return &v1beta2.SpiceDBObject{
		Kind: convertValueOrSelectorTo(src.Kind),
		Name: convertValueOrSelectorTo(src.Name),
	}
}

func spiceDBObjectFrom(src *v1beta2.SpiceDBObject) *AuthzedObject {
	if src == nil {
		return nil
	}
	return &AuthzedObject{
		Kind: convertValueOrSelectorFrom(src.Kind),
		Name: convertValueOrSelectorFrom(src.Name),
	}
}

func convertDenyWithSpecTo(src *DenyWithSpec) *v1beta2.DenyWithSpec {
	if src == nil {
		return nil
	}
	return &v1beta2.DenyWithSpec{
		Code:    v1beta2.DenyWithCode(src.Code),
		Headers: convertNamedValuesOrSelectorsTo(src.Headers),
		Message: convertPtrValueOrSelectorTo(src.Message),
		Body:    convertPtrValueOrSelectorTo(src.Body),
	}
}

func convertDenyWithSpecFrom(src *v1beta2.DenyWithSpec) *DenyWithSpec {
	if src == nil {
		return nil
	}
	return &DenyWithSpec{
		Code:    DenyWith_Code(src.Code),
		Headers: convertNamedValuesOrSelectorsFrom(src.Headers),
		Message: convertPtrValueOrSelectorFrom(src.Message),
		Body:    convertPtrValueOrSelectorFrom(src.Body),
	}
}

func convertSuccessResponseTo(src *Response) (string, v1beta2.SuccessResponseSpec) {
	response := v1beta2.SuccessResponseSpec{
		CommonEvaluatorSpec: v1beta2.CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
			Cache:      convertEvaluatorCachingTo(src.Cache),
		},
		Key: src.WrapperKey,
	}

	switch src.GetType() {
	case ResponsePlain:
		selector := v1beta2.PlainAuthResponseSpec(convertValueOrSelectorTo(StaticOrDynamicValue(*src.Plain)))
		response.Plain = &selector
	case ResponseDynamicJSON:
		response.Json = &v1beta2.JsonAuthResponseSpec{
			Properties: convertNamedValuesOrSelectorsTo(src.JSON.Properties),
		}
	case ResponseWristband:
		response.Wristband = &v1beta2.WristbandAuthResponseSpec{
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
			key := &v1beta2.WristbandSigningKeyRef{
				Name:      keySrc.Name,
				Algorithm: v1beta2.WristbandSigningKeyAlgorithm(keySrc.Algorithm),
			}
			response.Wristband.SigningKeyRefs = append(response.Wristband.SigningKeyRefs, key)
		}
	}

	return src.Name, response
}

func convertSuccessResponseFrom(name string, src v1beta2.SuccessResponseSpec, wrapper string) *Response {
	response := &Response{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
		Cache:      convertEvaluatorCachingFrom(src.Cache),
		Wrapper:    Response_Wrapper(wrapper),
		WrapperKey: src.Key,
	}

	switch src.GetMethod() {
	case v1beta2.PlainAuthResponse:
		selector := Response_Plain(convertValueOrSelectorFrom(v1beta2.ValueOrSelector(*src.Plain)))
		response.Plain = &selector
	case v1beta2.JsonAuthResponse:
		response.JSON = &Response_DynamicJSON{
			Properties: convertNamedValuesOrSelectorsFrom(src.Json.Properties),
		}
	case v1beta2.WristbandAuthResponse:
		response.Wristband = &Response_Wristband{
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
			key := SigningKeyRef{
				Name:      keySrc.Name,
				Algorithm: SigningKeyAlgorithm(keySrc.Algorithm),
			}
			response.Wristband.SigningKeyRefs = append(response.Wristband.SigningKeyRefs, &key)
		}
	}

	return response
}

func convertCallbackTo(src *Callback) (string, v1beta2.CallbackSpec) {
	callback := v1beta2.CallbackSpec{
		CommonEvaluatorSpec: v1beta2.CommonEvaluatorSpec{
			Priority:   src.Priority,
			Metrics:    src.Metrics,
			Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefTo),
		},
	}

	switch src.GetType() {
	case CallbackHTTP:
		callback.Http = convertHttpEndpointSpecTo(src.HTTP)
	}

	return src.Name, callback
}

func convertCallbackFrom(name string, src v1beta2.CallbackSpec) *Callback {
	callback := &Callback{
		Name:       name,
		Priority:   src.Priority,
		Metrics:    src.Metrics,
		Conditions: utils.Map(src.Conditions, convertPatternExpressionOrRefFrom),
	}

	switch src.GetMethod() {
	case v1beta2.HttpCallback:
		callback.HTTP = convertHttpEndpointSpecFrom(src.Http)
	}

	return callback
}

func convertStatusTo(src AuthConfigStatus) v1beta2.AuthConfigStatus {
	return v1beta2.AuthConfigStatus{
		Conditions: utils.Map(src.Conditions, func(conditionSrc Condition) v1beta2.AuthConfigStatusCondition {
			condition := v1beta2.AuthConfigStatusCondition{
				Type:               v1beta2.StatusConditionType(conditionSrc.Type),
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

func convertStatusFrom(src v1beta2.AuthConfigStatus) AuthConfigStatus {
	return AuthConfigStatus{
		Conditions: utils.Map(src.Conditions, func(conditionSrc v1beta2.AuthConfigStatusCondition) Condition {
			condition := Condition{
				Type:               ConditionType(conditionSrc.Type),
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

func convertStatusSummaryTo(src Summary) v1beta2.AuthConfigStatusSummary {
	hostsReady := make([]string, len(src.HostsReady))
	copy(hostsReady, src.HostsReady)

	return v1beta2.AuthConfigStatusSummary{
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

func convertStatusSummaryFrom(src v1beta2.AuthConfigStatusSummary) Summary {
	hostsReady := make([]string, len(src.HostsReady))
	copy(hostsReady, src.HostsReady)

	return Summary{
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
