package envoy.authz

import input.attributes.request.http as http_request

jwks = `{
  "keys": [
    {
      "kid": "OjWSsDoNdjuMwe9MVSbg2Ow6acIRGMBpnn-ZPankrMI",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "ze3vCqCMNWp7R1-vDZWbUFQU-o-DepSr5ZblZuCsIYfQGQFaupocWvGMRGN5ebH-6EnY7D-s8HvseV4udYe4_I8kAfR6OWR0qWjfoe4tmJijslBS5GijdmNH9ENvtgWq6GXNdoi3QQ_doXRw04QR8XEiCzTa3_toQ4ebXukOz3LAPWhDgB3fVUcOkl0W79Id3ofA_9bmfeLAzc0Bl8S2mmMpM3ZOiOsaBOPo46PZqeuRf7QzyKParnyHU_AlMOl8FJnhpvQei1Q-GEq3cfd2NRxQ6kvw5NBwABVOKstdxtwbkRbnH6Umsq7IYUbvO31lsx_NpKehuYsGzyGZgtOBhw",
      "e": "AQAB",
      "x5c": [
        "MIICmTCCAYECBgF01EJ0PzANBgkqhkiG9w0BAQsFADAQMQ4wDAYDVQQDDAVvc3RpYTAeFw0yMDA5MjgxMDI3MzlaFw0zMDA5MjgxMDI5MTlaMBAxDjAMBgNVBAMMBW9zdGlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAze3vCqCMNWp7R1+vDZWbUFQU+o+DepSr5ZblZuCsIYfQGQFaupocWvGMRGN5ebH+6EnY7D+s8HvseV4udYe4/I8kAfR6OWR0qWjfoe4tmJijslBS5GijdmNH9ENvtgWq6GXNdoi3QQ/doXRw04QR8XEiCzTa3/toQ4ebXukOz3LAPWhDgB3fVUcOkl0W79Id3ofA/9bmfeLAzc0Bl8S2mmMpM3ZOiOsaBOPo46PZqeuRf7QzyKParnyHU/AlMOl8FJnhpvQei1Q+GEq3cfd2NRxQ6kvw5NBwABVOKstdxtwbkRbnH6Umsq7IYUbvO31lsx/NpKehuYsGzyGZgtOBhwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB0FimgiqoUSdY/R/n+/iNK5lhtmJ0RkagdTfVpvNNUqazSI3QxiBmLlShs3tEuk1slxuTaLRh7NWo9MvtjXJJCmVWKRcq17yJclb4ICutw1To+09U0v4NTRtwTGauFVssDCu/vq74AfFhlWB1YJ7ktMyoCKX/HAKmSEMd+h4XrEi248C6s7/8z1m6CODv0wlTPE2SR/jcmv5oVPm1LJMx7LHoqT1Oxa2TD7GVnO6ronfEwAceINxZKHzwkA6xASuKsE1jevtl3p+bepOiE0qCEEhEAKj2fU4NwV0A24TBc+c0dj6eXF47hJcTtosUVicIzQdXra6qZWXProjPXVxwn"
      ],
      "x5t": "LaYFwMQHEM1dWj8buFi2zck-DCs",
      "x5t#S256": "T0WXjHg-5gBdIviS13GJtomQRqAofF3ylks0Xo3xEt0"
    }
  ]
}`

token = {"valid": valid, "header": header, "payload": payload} {
  [_, encoded] := split(http_request.headers.authorization, " ")
  valid := io.jwt.verify_rs256(encoded, jwks)
  [header, payload, _] := io.jwt.decode(encoded)
}

default allow = false

allow = response {
  valid_token
  action_allowed
  response := {
    "allowed": true,
    "headers": {"x-current-user": token.payload.name}
  }
}

valid_token {
  token.valid
  now := time.now_ns() / 1000000000
  nbf := object.get(token.payload, "nbf", 0)
  nbf <= now
  now < token.payload.exp
}

action_allowed {
  http_request.method == "GET"
  token.payload.realm_access.roles[_] == "provider"
  glob.match("/service*", [], http_request.path)
}
