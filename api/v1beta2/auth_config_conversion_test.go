package v1beta2

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kuadrant/authorino/api/v1beta1"
)

func TestConvertTo(t *testing.T) {
	converted := &v1beta1.AuthConfig{}
	authConfig().ConvertTo(converted)

	sort.Slice(converted.Spec.Identity, func(i, j int) bool {
		return converted.Spec.Identity[i].Name < converted.Spec.Identity[j].Name
	})
	sort.Slice(converted.Spec.Metadata, func(i, j int) bool {
		return converted.Spec.Metadata[i].Name < converted.Spec.Metadata[j].Name
	})
	sort.Slice(converted.Spec.Authorization, func(i, j int) bool {
		return converted.Spec.Authorization[i].Name < converted.Spec.Authorization[j].Name
	})
	sort.Slice(converted.Spec.Response, func(i, j int) bool {
		return converted.Spec.Response[i].Name < converted.Spec.Response[j].Name
	})
	for idx := range converted.Spec.Response {
		if converted.Spec.Response[idx].Wristband != nil {
			sort.Slice(converted.Spec.Response[idx].Wristband.CustomClaims, func(i, j int) bool {
				return converted.Spec.Response[idx].Wristband.CustomClaims[i].Name < converted.Spec.Response[idx].Wristband.CustomClaims[j].Name
			})
		}
		if converted.Spec.Response[idx].JSON != nil {
			sort.Slice(converted.Spec.Response[idx].JSON.Properties, func(i, j int) bool {
				return converted.Spec.Response[idx].JSON.Properties[i].Name < converted.Spec.Response[idx].JSON.Properties[j].Name
			})
		}
	}
	sort.Slice(converted.Spec.Callbacks, func(i, j int) bool {
		return converted.Spec.Callbacks[i].Name < converted.Spec.Callbacks[j].Name
	})
	sort.Slice(converted.Spec.DenyWith.Unauthenticated.Headers, func(i, j int) bool {
		return converted.Spec.DenyWith.Unauthenticated.Headers[i].Name < converted.Spec.DenyWith.Unauthenticated.Headers[j].Name
	})
	sort.Slice(converted.Spec.DenyWith.Unauthorized.Headers, func(i, j int) bool {
		return converted.Spec.DenyWith.Unauthorized.Headers[i].Name < converted.Spec.DenyWith.Unauthorized.Headers[j].Name
	})

	expected := hubAuthConfig()
	if !reflect.DeepEqual(expected, converted) {
		t.Error(cmp.Diff(expected, converted))
	}
}

func TestConvertFrom(t *testing.T) {
	converted := &AuthConfig{}
	converted.ConvertFrom(hubAuthConfig())
	expected := authConfig()
	if !reflect.DeepEqual(expected, converted) {
		t.Error(cmp.Diff(expected, converted))
	}
}

func authConfig() *AuthConfig {
	authConfig := &AuthConfig{}
	err := json.Unmarshal([]byte(`
	{
		"metadata": {
			"name": "auth-config"
		},
		"spec": {
			"authentication": {
				"anonymousAccess": {
					"anonymous": {},
					"credentials": {
						"authorizationHeader": {}
					},
					"priority": 1
				},
				"apiKeyUsers": {
					"apiKey": {
						"selector": {
							"matchLabels": {
								"app": "talker-api",
								"talker-api/credential-kind": "api-key"
							}
						}
					},
					"credentials": {
						"authorizationHeader": {
							"prefix": "API-KEY"
						}
					},
					"overrides": {
						"groups": {
							"value": [
								"admin"
							]
						}
					}
				},
				"fromEnvoy": {
					"credentials": {
						"authorizationHeader": {}
					},
					"plain": {
						"selector": "context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.jwt_authn|verified_jwt"
					},
					"when": [
						{
							"operator": "neq",
							"selector": "context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.jwt_authn"
						}
					]
				},
				"k8sServiceAccountTokens": {
					"credentials": {
						"authorizationHeader": {}
					},
					"kubernetesTokenReview": {
						"audiences": [
							"talker-api.default.svc.cluster.local"
						]
					}
				},
				"mtlsUsers": {
					"credentials": {
						"authorizationHeader": {}
					},
					"x509": {
						"selector": {
							"matchLabels": {
								"app": "talker-api",
								"talker-api/credential-kind": "ca-cert"
							}
						}
					}
				},
				"oauth2OpaqueTokens": {
					"credentials": {
						"authorizationHeader": {}
					},
					"oauth2Introspection": {
						"credentialsRef": {
							"name": "oauth2-introspection-credentials"
						},
						"endpoint": "https://accounts.company.com/oauth2/v1/introspect"
					},
					"overrides": {
						"jwtRBAC": {
							"value": true
						}
					}
				},
				"oidcServerUsers": {
					"credentials": {
						"authorizationHeader": {}
					},
					"defaults": {
						"username": {
							"selector": "auth.identity.preferred_username"
						}
					},
					"jwt": {
						"issuerUrl": "https://accounts.company.com",
						"ttl": 3600
					},
					"overrides": {
						"jwtRBAC": {
							"value": true
						}
					}
				}
			},
			"authorization": {
				"deny20percent": {
					"opa": {
						"rego": "allow { rand.intn(\"foo\", 100) < 80 }"
					},
					"priority": 1
				},
				"externalOpaPolicy": {
					"opa": {
						"externalPolicy": {
							"credentials": {
								"authorizationHeader": {}
							},
							"ttl": 3600,
							"url": "https://raw.githubusercontent.com/repo/authorino-opa/main/allowed-methods.rego"
						}
					}
				},
				"externalSpicedbPolicy": {
					"spicedb": {
						"endpoint": "spicedb.spicedb.svc.cluster.local:50051",
						"insecure": true,
						"permission": {
							"selector": "context.request.http.method.@replace:{\"old\":\"GET\",\"new\":\"read\"}.@replace:{\"old\":\"POST\",\"new\":\"write\"}"
						},
						"resource": {
							"kind": {
								"value": "blog/post"
							},
							"name": {
								"selector": "context.request.http.path.@extract:{\"sep\":\"/\",\"pos\":2}"
							}
						},
						"sharedSecretRef": {
							"key": "grpc-preshared-key",
							"name": "spicedb"
						},
						"subject": {
							"kind": {
								"value": "blog/user"
							},
							"name": {
								"selector": "auth.identity.metadata.annotations.username"
							}
						}
					}
				},
				"inlineRego": {
					"opa": {
						"allValues": true,
						"rego": "country = object.get(object.get(input.auth.metadata, \"geo-info\", {}), \"country_iso_code\", null)\nallow {\n  allowed_countries := [\"ES\", \"FR\", \"IT\"]\n  allowed_countries[_] == country\n}\n"
					}
				},
				"kubernetesRBAC": {
					"kubernetesSubjectAccessReview": {
						"user": {
							"selector": "auth.identity.username"
						}
					},
					"when": [
						{
							"patternRef": "admin-path"
						},
						{
							"operator": "eq",
							"selector": "auth.identity.kubernetes-rbac",
							"value": "true"
						}
					]
				},
				"simplePatternMatching": {
					"patternMatching": {
						"patterns": [
							{
								"operator": "incl",
								"selector": "auth.identity.roles",
								"value": "admin"
							}
						]
					},
					"when": [
						{
							"patternRef": "admin-path"
						},
						{
							"operator": "eq",
							"selector": "auth.identity.jwtRBAC",
							"value": "true"
						}
					]
				},
				"timestamp": {
					"opa": {
						"allValues": true,
						"rego": "now = time.now_ns() / 1000000000\nallow = true\n"
					},
					"priority": 20
				}
			},
			"callbacks": {
				"telemetry": {
					"http": {
						"body": {
							"selector": "\\{\"requestId\":context.request.http.id,\"username\":\"{auth.identity.username}\",\"authorizationResult\":{auth.authorization}\\}\n"
						},
						"contentType": "application/x-www-form-urlencoded",
						"credentials": {
							"authorizationHeader": {}
						},
						"method": "POST",
						"oauth2": {
							"cache": true,
							"clientId": "talker-api",
							"clientSecretRef": {
								"key": "client-secret",
								"name": "talker-api-telemetry-credentials"
							},
							"tokenUrl": "https://accounts.company.com/oauth2/v1/token"
						},
						"url": "http://telemetry.server"
					}
				}
			},
			"hosts": [
				"talker-api.127.0.0.1.nip.io",
				"talker-api.default.svc.cluster.local"
			],
			"metadata": {
				"geoInfo": {
					"cache": {
						"key": {
							"selector": "context.request.http.headers.x-forwarded-for.@extract:{\"sep\":\",\"}"
						},
						"ttl": 3600
					},
					"http": {
						"contentType": "application/x-www-form-urlencoded",
						"credentials": {
							"authorizationHeader": {}
						},
						"headers": {
							"Accept": {
								"value": "application/json"
							}
						},
						"method": "GET",
						"sharedSecretRef": {
							"key": "shared-secret",
							"name": "ip-location"
						},
						"url": "http://ip-location.authorino.svc.cluster.local:3000/{context.request.http.headers.x-forwarded-for.@extract:{\"sep\":\",\"}}"
					},
					"metrics": true
				},
				"oidcUserInfo": {
					"userInfo": {
						"identitySource": "oidcServerUsers"
					}
				},
				"umaResourceInfo": {
					"cache": {
						"key": {
							"selector": "context.request.http.path"
						},
						"ttl": 60
					},
					"uma": {
						"credentialsRef": {
							"name": "talker-api-uma-credentials"
						},
						"endpoint": "http://keycloak.authorino.svc.cluster.local:8080/auth/realms/kuadrant"
					},
					"when": [
						{
							"patternRef": "resourcePath"
						}
					]
				}
			},
			"patterns": {
				"adminPath": [
					{
						"operator": "matches",
						"selector": "context.request.http.path",
						"value": "^/admin(/.*)?$"
					}
				],
				"resourcePath": [
					{
						"operator": "matches",
						"selector": "context.request.http.path",
						"value": "^/greetings/\\d+$"
					}
				]
			},
			"response": {
				"success": {
					"dynamicMetadata": {
						"username": {
							"key": "",
							"plain": {
								"selector": "auth.identity.username"
							}
						}
					},
					"headers": {
						"festival-wristband": {
							"key": "x-wristband-token",
							"wristband": {
								"customClaims": {
									"scope": {
										"selector": "context.request.http.method.@case:lower"
									},
									"uri": {
										"selector": "context.request.http.path"
									},
									"username": {
										"selector": "auth.identity.username"
									}
								},
								"issuer": "https://authorino-authorino-oidc.authorino.svc.cluster.local:8083/authorino/e2e-test/festival-wristband",
								"signingKeyRefs": [
									{
										"algorithm": "ES256",
										"name": "wristband-signing-key"
									}
								],
								"tokenDuration": 300
							}
						},
						"x-auth-data": {
							"json": {
								"properties": {
									"geo": {
										"selector": "auth.metadata.geoInfo"
									},
									"timestamp": {
										"selector": "auth.authorization.timestamp"
									},
									"username": {
										"selector": "auth.identity.username"
									}
								}
							},
							"key": ""
						},
						"x-auth-service": {
							"key": "",
							"plain": {
								"value": "Authorino"
							}
						}
					}
				},
				"unauthenticated": {
					"message": {
						"value": "Authentication failed"
					}
				},
				"unauthorized": {
					"body": {
						"value": "{\n  \"kind\": \"Error\",\n  \"id\": \"403\",\n  \"href\": \"/forbidden\",\n  \"code\": \"FORBIDDEN-403\",\n  \"reason\": \"Forbidden\"\n}\n"
					},
					"headers": {
						"content-type": {
							"value": "application/json"
						},
						"random": {
							"selector": "auth.authorization.deny20percent"
						}
					},
					"message": {
						"value": "Access denied"
					}
				}
			},
			"when": [
				{
					"operator": "neq",
					"selector": "context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.skipper_lua_filter|skip",
					"value": "true"
				}
			]
		},
		"status": {
			"summary": {
				"ready": false,
				"hostsReady": [],
				"numHostsReady": "",
				"numIdentitySources": 0,
				"numMetadataSources": 0,
				"numAuthorizationPolicies": 0,
				"numResponseItems": 0,
				"festivalWristbandEnabled": false
			}
		}
	}`), &authConfig)
	if err != nil {
		panic(err)
	}
	return authConfig
}

func hubAuthConfig() *v1beta1.AuthConfig {
	authConfig := &v1beta1.AuthConfig{}
	err := json.Unmarshal([]byte(`
	{
		"metadata": {
			"name": "auth-config"
		},
		"spec": {
			"authorization": [
				{
					"metrics": false,
					"name": "deny20percent",
					"opa": {
						"allValues": false,
						"inlineRego": "allow { rand.intn(\"foo\", 100) < 80 }"
					},
					"priority": 1
				},
				{
					"metrics": false,
					"name": "externalOpaPolicy",
					"opa": {
						"allValues": false,
						"externalRegistry": {
							"credentials": {
								"in": "authorization_header",
								"keySelector": ""
							},
							"endpoint": "https://raw.githubusercontent.com/repo/authorino-opa/main/allowed-methods.rego",
							"ttl": 3600
						}
					},
					"priority": 0
				},
				{
					"authzed": {
						"endpoint": "spicedb.spicedb.svc.cluster.local:50051",
						"insecure": true,
						"permission": {
							"valueFrom": {
								"authJSON": "context.request.http.method.@replace:{\"old\":\"GET\",\"new\":\"read\"}.@replace:{\"old\":\"POST\",\"new\":\"write\"}"
							}
						},
						"resource": {
							"kind": {
								"value": "blog/post",
								"valueFrom": {}
							},
							"name": {
								"valueFrom": {
									"authJSON": "context.request.http.path.@extract:{\"sep\":\"/\",\"pos\":2}"
								}
							}
						},
						"sharedSecretRef": {
							"key": "grpc-preshared-key",
							"name": "spicedb"
						},
						"subject": {
							"kind": {
								"value": "blog/user",
								"valueFrom": {}
							},
							"name": {
								"valueFrom": {
									"authJSON": "auth.identity.metadata.annotations.username"
								}
							}
						}
					},
					"metrics": false,
					"name": "externalSpicedbPolicy",
					"priority": 0
				},
				{
					"metrics": false,
					"name": "inlineRego",
					"opa": {
						"allValues": true,
						"inlineRego": "country = object.get(object.get(input.auth.metadata, \"geo-info\", {}), \"country_iso_code\", null)\nallow {\n  allowed_countries := [\"ES\", \"FR\", \"IT\"]\n  allowed_countries[_] == country\n}\n"
					},
					"priority": 0
				},
				{
					"kubernetes": {
						"user": {
							"valueFrom": {
								"authJSON": "auth.identity.username"
							}
						}
					},
					"metrics": false,
					"name": "kubernetesRBAC",
					"priority": 0,
					"when": [
						{
							"patternRef": "admin-path"
						},
						{
							"operator": "eq",
							"selector": "auth.identity.kubernetes-rbac",
							"value": "true"
						}
					]
				},
				{
					"json": {
						"rules": [
							{
								"operator": "incl",
								"selector": "auth.identity.roles",
								"value": "admin"
							}
						]
					},
					"metrics": false,
					"name": "simplePatternMatching",
					"priority": 0,
					"when": [
						{
							"patternRef": "admin-path"
						},
						{
							"operator": "eq",
							"selector": "auth.identity.jwtRBAC",
							"value": "true"
						}
					]
				},
				{
					"metrics": false,
					"name": "timestamp",
					"opa": {
						"allValues": true,
						"inlineRego": "now = time.now_ns() / 1000000000\nallow = true\n"
					},
					"priority": 20
				}
			],
			"callbacks": [
				{
					"http": {
						"body": {
							"valueFrom": {
								"authJSON": "\\{\"requestId\":context.request.http.id,\"username\":\"{auth.identity.username}\",\"authorizationResult\":{auth.authorization}\\}\n"
							}
						},
						"contentType": "application/x-www-form-urlencoded",
						"credentials": {
							"in": "authorization_header",
							"keySelector": ""
						},
						"endpoint": "http://telemetry.server",
						"method": "POST",
						"oauth2": {
							"cache": true,
							"clientId": "talker-api",
							"clientSecretRef": {
								"key": "client-secret",
								"name": "talker-api-telemetry-credentials"
							},
							"tokenUrl": "https://accounts.company.com/oauth2/v1/token"
						}
					},
					"metrics": false,
					"name": "telemetry",
					"priority": 0
				}
			],
			"denyWith": {
				"unauthenticated": {
					"message": {
						"value": "Authentication failed",
						"valueFrom": {}
					}
				},
				"unauthorized": {
					"body": {
						"value": "{\n  \"kind\": \"Error\",\n  \"id\": \"403\",\n  \"href\": \"/forbidden\",\n  \"code\": \"FORBIDDEN-403\",\n  \"reason\": \"Forbidden\"\n}\n"
					},
					"headers": [
						{
							"name": "content-type",
							"value": "application/json",
							"valueFrom": {}
						},
						{
							"name": "random",
							"valueFrom": {
								"authJSON": "auth.authorization.deny20percent"
							}
						}
					],
					"message": {
						"value": "Access denied",
						"valueFrom": {}
					}
				}
			},
			"hosts": [
				"talker-api.127.0.0.1.nip.io",
				"talker-api.default.svc.cluster.local"
			],
			"identity": [
				{
					"anonymous": {},
					"credentials": {
						"in": "authorization_header",
						"keySelector": ""
					},
					"metrics": false,
					"name": "anonymousAccess",
					"priority": 1
				},
				{
					"apiKey": {
						"allNamespaces": false,
						"selector": {
							"matchLabels": {
								"app": "talker-api",
								"talker-api/credential-kind": "api-key"
							}
						}
					},
					"credentials": {
						"in": "authorization_header",
						"keySelector": "API-KEY"
					},
					"extendedProperties": [
						{
							"name": "groups",
							"overwrite": true,
							"value": [
								"admin"
							],
							"valueFrom": {}
						}
					],
					"metrics": false,
					"name": "apiKeyUsers",
					"priority": 0
				},
				{
					"credentials": {
						"in": "authorization_header",
						"keySelector": ""
					},
					"metrics": false,
					"name": "fromEnvoy",
					"plain": {
						"authJSON": "context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.jwt_authn|verified_jwt"
					},
					"priority": 0,
					"when": [
						{
							"operator": "neq",
							"selector": "context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.jwt_authn"
						}
					]
				},
				{
					"credentials": {
						"in": "authorization_header",
						"keySelector": ""
					},
					"kubernetes": {
						"audiences": [
							"talker-api.default.svc.cluster.local"
						]
					},
					"metrics": false,
					"name": "k8sServiceAccountTokens",
					"priority": 0
				},
				{
					"credentials": {
						"in": "authorization_header",
						"keySelector": ""
					},
					"metrics": false,
					"mtls": {
						"allNamespaces": false,
						"selector": {
							"matchLabels": {
								"app": "talker-api",
								"talker-api/credential-kind": "ca-cert"
							}
						}
					},
					"name": "mtlsUsers",
					"priority": 0
				},
				{
					"credentials": {
						"in": "authorization_header",
						"keySelector": ""
					},
					"extendedProperties": [
						{
							"name": "jwtRBAC",
							"overwrite": true,
							"value": true,
							"valueFrom": {}
						}
					],
					"metrics": false,
					"name": "oauth2OpaqueTokens",
					"oauth2": {
						"credentialsRef": {
							"name": "oauth2-introspection-credentials"
						},
						"tokenIntrospectionUrl": "https://accounts.company.com/oauth2/v1/introspect"
					},
					"priority": 0
				},
				{
					"credentials": {
						"in": "authorization_header",
						"keySelector": ""
					},
					"extendedProperties": [
						{
							"name": "jwtRBAC",
							"overwrite": true,
							"value": true,
							"valueFrom": {}
						},
						{
							"name": "username",
							"overwrite": false,
							"valueFrom": {
								"authJSON": "auth.identity.preferred_username"
							}
						}
					],
					"metrics": false,
					"name": "oidcServerUsers",
					"oidc": {
						"endpoint": "https://accounts.company.com",
						"ttl": 3600
					},
					"priority": 0
				}
			],
			"metadata": [
				{
					"cache": {
						"key": {
							"valueFrom": {
								"authJSON": "context.request.http.headers.x-forwarded-for.@extract:{\"sep\":\",\"}"
							}
						},
						"ttl": 3600
					},
					"http": {
						"contentType": "application/x-www-form-urlencoded",
						"credentials": {
							"in": "authorization_header",
							"keySelector": ""
						},
						"endpoint": "http://ip-location.authorino.svc.cluster.local:3000/{context.request.http.headers.x-forwarded-for.@extract:{\"sep\":\",\"}}",
						"headers": [
							{
								"name": "Accept",
								"value": "application/json",
								"valueFrom": {}
							}
						],
						"method": "GET",
						"sharedSecretRef": {
							"key": "shared-secret",
							"name": "ip-location"
						}
					},
					"metrics": true,
					"name": "geoInfo",
					"priority": 0
				},
				{
					"metrics": false,
					"name": "oidcUserInfo",
					"priority": 0,
					"userInfo": {
						"identitySource": "oidcServerUsers"
					}
				},
				{
					"cache": {
						"key": {
							"valueFrom": {
								"authJSON": "context.request.http.path"
							}
						},
						"ttl": 60
					},
					"metrics": false,
					"name": "umaResourceInfo",
					"priority": 0,
					"uma": {
						"credentialsRef": {
							"name": "talker-api-uma-credentials"
						},
						"endpoint": "http://keycloak.authorino.svc.cluster.local:8080/auth/realms/kuadrant"
					},
					"when": [
						{
							"patternRef": "resourcePath"
						}
					]
				}
			],
			"patterns": {
				"adminPath": [
					{
						"operator": "matches",
						"selector": "context.request.http.path",
						"value": "^/admin(/.*)?$"
					}
				],
				"resourcePath": [
					{
						"operator": "matches",
						"selector": "context.request.http.path",
						"value": "^/greetings/\\d+$"
					}
				]
			},
			"response": [
				{
					"metrics": false,
					"name": "festival-wristband",
					"priority": 0,
					"wrapper": "httpHeader",
					"wrapperKey": "x-wristband-token",
					"wristband": {
						"customClaims": [
							{
								"name": "scope",
								"valueFrom": {
									"authJSON": "context.request.http.method.@case:lower"
								}
							},
							{
								"name": "uri",
								"valueFrom": {
									"authJSON": "context.request.http.path"
								}
							},
							{
								"name": "username",
								"valueFrom": {
									"authJSON": "auth.identity.username"
								}
							}
						],
						"issuer": "https://authorino-authorino-oidc.authorino.svc.cluster.local:8083/authorino/e2e-test/festival-wristband",
						"signingKeyRefs": [
							{
								"algorithm": "ES256",
								"name": "wristband-signing-key"
							}
						],
						"tokenDuration": 300
					}
				},
				{
					"metrics": false,
					"name": "username",
					"plain": {
						"valueFrom": {
							"authJSON": "auth.identity.username"
						}
					},
					"priority": 0,
					"wrapper": "envoyDynamicMetadata",
					"wrapperKey": ""
				},
				{
					"json": {
						"properties": [
							{
								"name": "geo",
								"valueFrom": {
									"authJSON": "auth.metadata.geoInfo"
								}
							},
							{
								"name": "timestamp",
								"valueFrom": {
									"authJSON": "auth.authorization.timestamp"
								}
							},
							{
								"name": "username",
								"valueFrom": {
									"authJSON": "auth.identity.username"
								}
							}
						]
					},
					"metrics": false,
					"name": "x-auth-data",
					"priority": 0,
					"wrapper": "httpHeader",
					"wrapperKey": ""
				},
				{
					"metrics": false,
					"name": "x-auth-service",
					"plain": {
						"value": "Authorino",
						"valueFrom": {}
					},
					"priority": 0,
					"wrapper": "httpHeader",
					"wrapperKey": ""
				}
			],
			"when": [
				{
					"operator": "neq",
					"selector": "context.metadata_context.filter_metadata.envoy\\.filters\\.http\\.skipper_lua_filter|skip",
					"value": "true"
				}
			]
		},
		"status": {
			"summary": {
				"ready": false,
				"hostsReady": [],
				"numHostsReady": "",
				"numIdentitySources": 0,
				"numMetadataSources": 0,
				"numAuthorizationPolicies": 0,
				"numResponseItems": 0,
				"festivalWristbandEnabled": false
			}
		}
	}`), &authConfig)
	if err != nil {
		panic(err)
	}
	return authConfig
}
