FROM envoyproxy/envoy-dev:latest

RUN apt-get update && apt-get -q install -y \
    curl
CMD /usr/local/bin/envoy \
	--config-path /etc/envoy.yaml \
	--service-cluster front-proxy \
	--log-level ${LOG_LEVEL} \
	--component-log-level ${COMPONENT_LOG_LEVEL} \
  --bootstrap-version 2
