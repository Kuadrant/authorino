#!/usr/bin/env bash
set -E
set -o functrace

launch_as() {
  local cmd_name=$1
  shift
  (time $@ || echo $cmd_name >> fail.txt) 2>&1 > $cmd_name.txt
}

function handle_error {
    local retval=$?
    local line=${last_lineno:-$1}
    echo "Failed at $line: $BASH_COMMAND"
    echo "Trace: " "$@"
    sleep 10
    echo "Dumping logs"
    cat envoy_logs.txt
    cat authorino_logs.txt
    cat keycloack_logs.txt

    exit $retval
}
if (( ${BASH_VERSION%%.*} <= 3 )) || [[ ${BASH_VERSION%.*} = 4.0 ]]; then
        trap '[[ $FUNCNAME = handle_error ]] || { last_lineno=$real_lineno; real_lineno=$LINENO; }' DEBUG
fi
trap 'handle_error $LINENO ${BASH_LINENO[@]}' ERR


kubectl -n authorino create secret generic userinfosecret \
--from-literal=clientID=authorino \
--from-literal=clientSecret='2e5246f2-f4ef-4d55-8225-36e725071dee'

kubectl -n authorino create secret generic umacredentialssecret \
--from-literal=clientID=pets-api \
--from-literal=clientSecret='523b92b6-625d-4e1e-a313-77e7a8ae4e88'

kubectl apply -f ./config/samples/config_v1beta1_service.yaml -n authorino

# List the current pods
kubectl get pods -n authorino

launch_as envoy_logs kubectl logs -n authorino deployments/envoy &
launch_as authorino_logs kubectl logs -n authorino deployments/authorino-controller-manager -c manager &
launch_as keycloack_logs kubectl logs -n authorino deployments/keycloak &

# TODO: This should actually wait for the status of the created Service to be set to ready
kubectl port-forward --namespace authorino deployment/envoy 8000:8000 &
kubectl port-forward --namespace authorino deployment/keycloak 8080:8080 &

# Keycloak takes forever to start
sleep 120

export ACCESS_TOKEN_JOHN=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=john' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

[ $(curl -o /dev/null -L -s -w "%{http_code}" -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/pets) -eq 200 ];
[ $(curl -o /dev/null -L -s -w "%{http_code}" -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/pets/1) -eq 200 ];
[ $(curl -o /dev/null -L -s -w "%{http_code}" -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JOHN" http://localhost:8000/stats) -eq 401 ];

export ACCESS_TOKEN_JANE=$(curl -k -d 'grant_type=password' -d 'client_id=demo' -d 'username=jane' -d 'password=p' "http://localhost:8080/auth/realms/ostia/protocol/openid-connect/token" | jq -r '.access_token')

[ $(curl -o /dev/null -L -s -w "%{http_code}" -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/pets) -eq 200 ];
[ $(curl -o /dev/null -L -s -w "%{http_code}" -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/stats) -eq 200 ];
[ $(curl -o /dev/null -L -s -w "%{http_code}" -H 'Host: echo-api' -H "Authorization: Bearer $ACCESS_TOKEN_JANE" http://localhost:8000/pets/1) -eq 401 ];
