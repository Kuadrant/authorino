# frozen_string_literal: true

require 'rack/auth/basic'
require 'logger'

require 'envoy/service/auth/v3/external_auth_services_pb'
require 'envoy/service/auth/v2/external_auth_pb'

require_relative 'config'
require_relative 'auth_service'
require_relative 'response_interceptor'

module RubyLogger
  def logger
    LOGGER
  end

  LOGGER = Logger.new(STDOUT)
end

# GRPC is the general RPC module
module GRPC
  # Inject the noop #logger if no module-level logger method has been injected.
  extend RubyLogger
end

Envoy::Service::Auth::V2::AttributeContext::HttpRequest.module_eval do
  def to_env
    headers.to_h.delete_if { |k, _| k.start_with?(':') }.transform_keys { |k| "HTTP_#{k.tr('-', '_').upcase}" }
  end
end

def main
  port = "0.0.0.0:#{ENV.fetch('PORT', 50051)}"
  config = Config.new(ENV.fetch('CONFIG', 'config.yml'))
  server = GRPC::RpcServer.new(interceptors: [ResponseInterceptor.new])
  server.add_http2_port(port, :this_port_is_insecure)
  GRPC.logger.info("... running insecurely on #{port}")
  server.handle(AuthService.new(config))

  # Runs the server with SIGHUP, SIGINT and SIGQUIT signal handlers to
  #   gracefully shutdown.
  # User could also choose to run server via call to run_till_terminated
  server.run_till_terminated_or_interrupted([1, +'int', +'SIGQUIT'])
end

main if __FILE__ == $0
