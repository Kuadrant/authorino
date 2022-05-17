#!/usr/bin/env bash

for cmd in realpath kubectl curl jq base64; do
	if ! s="$(type -p "$cmd")" || [[ -z $s ]]; then
    echo "$cmd command not found."
    exit 1
  fi
done

namespace=${NAMESPACE:-"authorino"}
authconfig=${AUTHCONFIG:-"$(dirname $(realpath $0))/authconfig.yaml"}

HOSTNAME="talker-api-authorino.127.0.0.1.nip.io"
IP_IN="109.69.200.56" # IT
IP_OUT="79.123.45.67" # GB

test_count=0

function wait_until {
  local what=$1; shift
  local condition=$1; shift
  printf "waiting ${what}"
  while : ; do
    if [[ "$($1)" =~ $condition ]]; then
      break
    fi
    printf "."
    sleep 3
  done
  echo " condition met"
}

function teardown {
  local result=$1

  echo
  echo
  echo $result

  for pid in $keycloak_pid $envoy_pid $kube_proxy_pid; do
    kill $pid 2>/dev/null
  done

  if [ "$result" == "FAIL" ]; then
    exit 1
  fi
}

function send {
  local expected=$1; shift
  local method=$1; shift
  local path=$1; shift
  local region=$1; shift
  local auth="$@"

  test_count=$((test_count+1))
  actual=$(curl -H "Host: $HOSTNAME" -H "$auth" -H "X-Forwarded-For: $region" -L -s -o /dev/null -w '%{http_code}' "http://localhost:8000$path" -X $method)

  if [ $actual -ne $expected ]; then
    echo
    echo "Test failed [#$test_count]:"
    echo "  $method $path"
    if [ "$auth" != "" ]; then
      echo "  $auth"
    fi
    echo "  X-Forwarded-For: $region"
    echo
    echo "  Expected: $expected"
    echo "  Actual: $actual"

    teardown "FAIL"
  else
    printf "."
  fi
}

function send_requests {
  local region=$1; shift
  local auth=$1; shift

  while IFS= read -r line; do
    req=${line##*( )}
    if [ "$req" != "" ]; then
      IFS=' ' read -ra r <<< "$req"
      send "${r[3]}" "${r[0]}" "${r[1]}" $region $auth
    fi
  done <<< "$@"
}

function send_k8s_sa_requests {
  local region=$1; shift
  local sa=$1; shift
  local access_token=""
  while [ "$access_token" == "" ]; do
    access_token=$(echo '{ "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": { "expirationSeconds": 600 } }' | kubectl create --raw /api/v1/namespaces/$namespace/serviceaccounts/$sa/token -f - | jq -r .status.token)
    sleep 1
  done
  local requests="$@"

  send_requests $region "Authorization: Bearer $access_token" "$requests"
}

function send_api_key_requests {
  local region=$1; shift
  local api_key_name=$1; shift
  local api_key=""
  while [ "$api_key" == "" ]; do
    api_key=$(kubectl -n $namespace get secret/$api_key_name -o jsonpath="{.data.api_key}" | base64 -d)
    sleep 1
  done
  local requests="$@"

  send_requests $region "X-API-KEY: $api_key" "$requests"
}

function send_oidc_requests {
  local region=$1; shift
  local user=$1; shift
  local passwd=$1; shift
  local access_token=""
  while [ "$access_token" == "" ]; do
    access_token=$(kubectl -n $namespace run token-$(hexdump -n 4 -e '4/4 "%0x"' /dev/urandom) --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.$namespace.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d "username=$user" -d "password=$passwd" 2>/dev/null | jq -r .access_token)
    sleep 1
  done
  local requests="$@"

  send_requests $region "Authorization: Bearer $access_token" "$requests"
}

function send_oauth_opaque_requests {
  local region=$1; shift
  local user=$1; shift
  local passwd=$1; shift
  local access_token=""
  while [ "$access_token" == "" ]; do
    access_token=$(kubectl -n $namespace run token-$(hexdump -n 4 -e '4/4 "%0x"' /dev/urandom) --attach --rm --restart=Never -q --image=curlimages/curl -- http://keycloak.$namespace.svc.cluster.local:8080/auth/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d "username=$user" -d "password=$passwd" 2>/dev/null | jq -r .access_token)
    sleep 1
  done
  local requests="$@"

  send_requests $region "Authorization: Opaque $access_token" "$requests"
}

function send_anonymous_requests {
  local region=$1; shift
  local requests="$@"

  send_requests $region "" "$requests"
}

kubectl -n kube-system wait --timeout=300s --for=condition=Available deployments --all
kubectl proxy --port=8181 2>&1 >/dev/null &
kube_proxy_pid=$!

kubectl -n $namespace apply -f https://raw.githubusercontent.com/Kuadrant/authorino-examples/main/ip-location/ip-location-deploy.yaml
kubectl -n $namespace wait --timeout=300s --for=condition=Available deployments --all
kubectl -n $namespace port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
envoy_pid=$!

# waiting for keycloak to be ready is hard
wait_until "keycloak ready" "Admin console listening" "kubectl -n $namespace logs $(kubectl -n $namespace get pods -l app=keycloak -o name) --tail 1"
kubectl -n $namespace port-forward deployment/keycloak 8080:8080 2>&1 >/dev/null &
keycloak_pid=$!
wait_until "oidc config ready" "^200$" "curl -o /dev/null -s -w %{http_code} --max-time 2 http://localhost:8080/auth/realms/kuadrant/.well-known/openid-configuration"

# authconfig
kubectl -n $namespace apply -f $authconfig
wait_until "authconfig ready" "^true$" "kubectl -n $namespace get authconfigs/e2e-test -o jsonpath={.status.ready}"

# tests
echo
echo "running tests"

send_k8s_sa_requests $IP_IN "app-1-sa" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 200
    GET /greetings/1 => 403"

send_k8s_sa_requests $IP_IN "app-2-sa" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 403"

send_api_key_requests $IP_IN "bob-api-key" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 200
    GET /greetings/1 => 403"

send_api_key_requests $IP_IN "alice-api-key" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 403"

send_oidc_requests $IP_IN "john" "p" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 200"

send_oidc_requests $IP_IN "jane" "p" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 200
    GET /greetings/1 => 403"

send_oauth_opaque_requests $IP_IN "peter" "p" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 403"

send_anonymous_requests $IP_IN "
    GET / => 200
    POST / => 401
    DELETE / => 401
    GET /admin => 401
    GET /greetings/1 => 401"

send_anonymous_requests $IP_OUT "
    GET / => 403"

teardown "SUCCESS"
