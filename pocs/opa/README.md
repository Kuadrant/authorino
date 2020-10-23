# OPA PoC

This PoC involves 3 components:
1. an **upstream service** - just a simple Python, not exposed, web service that expects a `x-current-user` header and prints its value in a greeting message
2. a front **Envoy service** - Envoy proxy with the [External Authorization Filter](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/ext_authz) enabled, configured to an OPA service to authenticate and authorize requests to the upstream service
3. an **Open Policy Agent (OPA) service** – verifies an OIDC token and evaluates a permission policy written in Rego lang

## Run

```shell
docker-compose up --build -d
```

## How it works

Say you got an OIDC access token (a JWT) that looks like the following one:

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "NA140bBru_K4q7fFzeTGaSpdxo6r9fZbd8kyaFvQolA"
  },
  "payload": {
    "iss": "https://token-issuer-endpoint",
    "iat": 1603450527,
    "exp": 1603450827,
    "typ": "Bearer",
    "azp": "some-client",
    "realm_access": {
      "roles": [
        "provider", # <======== this is important
        "offline_access",
        "uma_authorization"
      ]
    },
    "scope": "email profile",
    "email_verified": true,
    "name": "Authorized User",
    "preferred_username": "ican",
    "given_name": "Authorized",
    "family_name": "User"
  }
}
```

_Note:_ It's very important that the certificate used to sign the JWT (whose `kid` is in the token header) macthes a public key in the `jwks.json` certs file mounted and made available within the OPA service.

And then you send the following request to the Envoy service:

```shell
$ curl -v -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:8000/service"
*   Trying ::1:8000...
* TCP_NODELAY set
* Connected to localhost (::1) port 8000 (#0)
> GET /service HTTP/1.1
> Host: localhost:8000
> User-Agent: curl/7.65.3
> Accept: */*
> Authorization: Bearer [REDACTED]
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: text/html; charset=utf-8
< content-length: 40
< server: envoy
< date: Fri, 23 Oct 2020 11:56:04 GMT
< x-envoy-upstream-service-time: 2
<
* Connection #0 to host localhost left intact
Hello Authorized User from behind Envoy!
```

The Envoy proxy will contact in a gRPC call with the OPA service, which will verify and validate the access token and evaluate the permissions.
In this case, since the token owner has the "provider" role, the OPA service will authorize the request and thus the Envoy proxy will direct the traffic to the upstream service.

With a different access token, whose owner does NOT have the "provider" role or the token is invalid for any reason (invalid signature, expired, etc), you should expect the following:

```shell
$ curl -v -H "Authorization: Bearer $INVALID_ACCESS_TOKEN" "http://localhost:8000/service"
*   Trying ::1:8000...
* TCP_NODELAY set
* Connected to localhost (::1) port 8000 (#0)
> GET /service HTTP/1.1
> Host: localhost:8000
> User-Agent: curl/7.65.3
> Accept: */*
> Authorization: Bearer [REDACTED]
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< date: Fri, 23 Oct 2020 11:55:03 GMT
< server: envoy
< content-length: 0
<
* Connection #0 to host localhost left intact
```

The OPA service rejects the request, thus the Envoy proxy will respond with a 403 Forbidden and the upstream service will not be invoked.
