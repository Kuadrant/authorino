#!/bin/sh

/usr/local/bin/envoy -c "/etc/envoy-config/config.yaml" --service-cluster front-proxy
