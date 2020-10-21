#!/bin/sh

/usr/local/bin/envoy -c "/etc/envoy-config/opa-service/v1.yaml" --service-cluster front-proxy
