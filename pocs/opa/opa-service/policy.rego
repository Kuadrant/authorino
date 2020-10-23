package envoy.authz

import input.attributes.request.http as http_request

jwks = json.marshal(data.jwks)

token = {"valid": valid, "header": header, "payload": payload} {
  [_, encoded] := split(http_request.headers.authorization, " ")
  valid := io.jwt.verify_rs256(encoded, jwks)
  [header, payload, _] := io.jwt.decode(encoded)
}

default allow = false

allow = response {
  valid_token
  action_allowed
  username := object.get(token.payload, "name", token.payload.preferred_username)
  response := {
    "allowed": true,
    "headers": {"x-current-user": username}
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
