#!/usr/bin/env bash

for cmd in realpath kubectl curl jq base64; do
	if ! s="$(type -p "$cmd")" || [[ -z $s ]]; then
    echo "$cmd command not found."
    exit 1
  fi
done

namespace=${NAMESPACE:-"authorino"}
authconfig_version=${AUTHCONFIG_VERSION:-"v1beta3"}
authconfig=${AUTHCONFIG:-"$(dirname $(realpath $0))/${authconfig_version}/authconfig.yaml"}
authconfig_invalid=${AUTHCONFIG_INVALID:-"$(dirname $(realpath $0))/${authconfig_version}/authconfig-invalid.yaml"}
verbose=${VERBOSE}
timeout=${TIMEOUT:-"600"}

HOSTNAME="talker-api.127.0.0.1.nip.io"
IP_IN="109.69.200.56" # IT
IP_OUT="79.123.45.67" # GB

SUCCESS_MESSAGE="\033[32mSUCCESS\033[0m"
FAIL_MESSAGE="\033[31mFAIL\033[0m"

test_count=0

function wait_until {
  local what=$1; shift
  local condition=$1; shift
  local start_time=$SECONDS
  printf "waiting ${what}"
  while : ; do
    if [[ "$($1)" =~ $condition ]]; then
      break
    fi
    printf "."
    sleep 3
    if [ $(($SECONDS - $start_time)) -gt $timeout ]; then
      printf " (timeout)"
      teardown "$FAIL_MESSAGE"
    fi
  done
  echo " condition met"
}

function teardown {
  local result=$1

  echo
  echo
  printf "$result\n"

  for pid in $keycloak_pid $envoy_pid $wristband_pid; do
    kill $pid 2>/dev/null
  done

  if [[ "$result" =~ "FAIL" ]]; then
    exit 1
  fi
}

function send {
  local expected=$1; shift
  local protocol=$1; shift
  local host=$1; shift
  local port=$1; shift
  local method=$1; shift
  local path=$1; shift
  local region=$1; shift
  local auth="$@"

  test_count=$((test_count+1))
  actual=$(curl -H "Host: $host" -H "$auth" -H "X-Forwarded-For: $region" -k -L -s -o /dev/null -w '%{http_code}' "${protocol}://localhost:${port}${path}" -X $method)

  local target="$method\t$protocol://$host:$port$path"

  if [ $actual -ne $expected ]; then
    echo
    echo "Test failed [#$test_count]:"
    echo -e "  $target"
    if [ "$auth" != "" ]; then
      echo "  $auth"
    fi
    echo "  X-Forwarded-For: $region"
    echo
    echo "  Expected: $expected"
    echo "  Actual: $actual"

    teardown "$FAIL_MESSAGE"
  else
    if [ "$verbose" == "1" ]; then
      echo -e "[#$test_count]\tExpected: $expected\tActual: $actual\t$target"
    else
      printf "\033[32m.\033[0m"
    fi
  fi
}

function send_requests {
  local protocol=$1; shift
  local host=$1; shift
  local port=$1; shift
  local region=$1; shift
  local auth=$1; shift

  while IFS= read -r line; do
    req=${line##*( )}
    if [ "$req" != "" ]; then
      IFS=' ' read -ra r <<< "$req"
      send "${r[3]}" $protocol $host $port "${r[0]}" "${r[1]}" $region $auth
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

  send_requests "http" "$HOSTNAME" "8000" $region "Authorization: Bearer $access_token" "$requests"
}

function send_api_key_requests {
  local region=$1; shift
  local api_key=$1; shift
  local requests="$@"

  send_requests "http" "$HOSTNAME" "8000" $region "X-API-KEY: $api_key" "$requests"
}

function send_oidc_requests {
  local region=$1; shift
  local user=$1; shift
  local passwd=$1; shift
  local access_token=""
  while [ "$access_token" == "" ]; do
    access_token=$(kubectl -n $namespace run token-$(hexdump -n 4 -e '4/4 "%0x"' /dev/urandom) --attach --rm --restart=Never -q --image=curlimages/curl:8.1.1 -- http://keycloak.$namespace.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d "username=$user" -d "password=$passwd" 2>/dev/null | jq -r .access_token)
    sleep 1
  done
  local requests="$@"

  send_requests "http" "$HOSTNAME" "8000" $region "Authorization: Bearer $access_token" "$requests"
}

function send_oauth_opaque_requests {
  local region=$1; shift
  local user=$1; shift
  local passwd=$1; shift
  local access_token=""
  while [ "$access_token" == "" ]; do
    access_token=$(kubectl -n $namespace run token-$(hexdump -n 4 -e '4/4 "%0x"' /dev/urandom) --attach --rm --restart=Never -q --image=curlimages/curl:8.1.1 -- http://keycloak.$namespace.svc.cluster.local:8080/realms/kuadrant/protocol/openid-connect/token -s -d 'grant_type=password' -d 'client_id=demo' -d "username=$user" -d "password=$passwd" 2>/dev/null | jq -r .access_token)
    sleep 1
  done
  local requests="$@"

  send_requests "http" "$HOSTNAME" "8000" $region "Authorization: Opaque $access_token" "$requests"
}

function send_anonymous_requests {
  local region=$1; shift
  local requests="$@"

  send_requests "http" "$HOSTNAME" "8000" $region "" "$requests"
}

kubectl -n kube-system wait --timeout=300s --for=condition=Available deployments --all

kubectl -n $namespace apply -f https://raw.githubusercontent.com/Kuadrant/authorino-examples/main/ip-location/ip-location-deploy.yaml
kubectl -n $namespace wait --timeout=300s --for=condition=Available deployments --all
kubectl -n $namespace port-forward deployment/envoy 8000:8000 2>&1 >/dev/null &
envoy_pid=$!

# waiting for keycloak to be ready is hard
wait_until "keycloak ready" "Listening on: http://0.0.0.0:8080" "kubectl -n $namespace logs $(kubectl -n $namespace get pods -l app=keycloak -o name)"
kubectl -n $namespace port-forward deployment/keycloak 8080:8080 2>&1 >/dev/null &
keycloak_pid=$!
wait_until "oidc config ready" "^200$" "curl -o /dev/null -s -w %{http_code} --max-time 2 http://localhost:8080/realms/kuadrant/.well-known/openid-configuration"

# authconfig - invalid
printf "testing invalid authconfig "
echo $(kubectl -n $namespace apply -f $authconfig_invalid --dry-run=server 2>&1) | grep "must validate one and only one schema (oneOf)" >/dev/null && printf "[$SUCCESS_MESSAGE]\n" || teardown "$FAIL_MESSAGE"

sleep 1

# authconfig - valid
echo "testing valid authconfig"

kubectl -n $namespace apply -f $authconfig
wait_until "authconfig ready" "^True$" "kubectl -n $namespace get authconfigs/e2e-test -o jsonpath={.status.conditions[?(@.type==\"Ready\")].status}"

kubectl -n $namespace port-forward services/authorino-authorino-oidc 8083:8083 2>&1 >/dev/null &
wristband_pid=$!

echo "sending multiple requests"

send_k8s_sa_requests $IP_IN "app-1-sa" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 200
    GET /greetings/1 => 403"

# Test #5 done
send_k8s_sa_requests $IP_IN "app-2-sa" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 403"

# Test #10 done
send_api_key_requests $IP_IN "ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 200
    GET /greetings/1 => 403"

# Test #15 done
send_api_key_requests $IP_IN "pR2zLorYFIYOE4LLiQAWMPIRei1YgRBy" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 403"

# Test #20 done
kubectl -n $namespace delete secret/alice-api-key 2>/dev/null >/dev/null && sleep 1

send_api_key_requests $IP_IN "pR2zLorYFIYOE4LLiQAWMPIRei1YgRBy" "
    POST / => 401"

# Test #21 done
send_api_key_requests $IP_IN "ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx" "
    POST / => 200"

# Test #22 done
send_oidc_requests $IP_IN "john" "p" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 200"

# Test #27 done
send_oidc_requests $IP_IN "jane" "p" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 200
    GET /greetings/1 => 403"

# Test #32 done
send_oauth_opaque_requests $IP_IN "peter" "p" "
    GET / => 200
    POST / => 200
    DELETE / => 403
    GET /admin => 403
    GET /greetings/1 => 403"

# Test #37 done
send_anonymous_requests $IP_IN "
    GET / => 200
    POST / => 401
    DELETE / => 401
    GET /admin => 401
    GET /greetings/1 => 401"

# Test #42 done
send_anonymous_requests $IP_OUT "
    GET / => 403"

# Test #43 done
send_requests "https" "authorino-authorino-oidc" "8083" $IP_IN "" "
    GET /authorino/e2e-test/wristband/.well-known/openid-configuration => 200
    GET /authorino/e2e-test/wristband/.well-known/openid-connect/certs => 200
    GET /authorino/e2e-test/invalid/.well-known/openid-configuration => 404
    GET /authorino/invalid/wristband/.well-known/openid-configuration => 404
    GET /invalid/e2e-test/wristband/.well-known/openid-configuration => 404
    GET /invalid => 404"

teardown "$SUCCESS_MESSAGE"
