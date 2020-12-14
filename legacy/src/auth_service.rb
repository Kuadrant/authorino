# frozen_string_literal: true

class AuthService
  def initialize(config)
    @config = config
    @registry = PolicyRegistry.setup!(config)
  end

  attr_reader :config

  include GRPC::GenericService

  self.marshal_class_method = :encode
  self.unmarshal_class_method = :decode
  self.service_name = 'envoy.service.auth.v2.Authorization'

  # Performs authorization check based on the attributes associated with the incoming request,
  # and returns status `OK` or not `OK`.
  rpc :Check, Envoy::Service::Auth::V2::CheckRequest, Envoy::Service::Auth::V2::CheckResponse

  def check(req, rest)
    GRPC.logger.debug(req.class.name) { req.to_json(emit_defaults: true) }
    host = req.attributes.request.http.host

    case service = config.for_host(host)
    when Config::Service
      context = Context.new(req, service)
      context.evaluate!

      if context.valid?
        return ok_response(req, service)
      else
        return denied_response('Not authorized')
      end
    end

    denied_response('Service not found', status: :not_found)
  end

  protected

  RESPONSE_CODES = {
    not_found: { grpc: GRPC::Core::StatusCodes::NOT_FOUND,         envoy: Envoy::Type::StatusCode::NotFound },
    forbidden: { grpc: GRPC::Core::StatusCodes::PERMISSION_DENIED, envoy: Envoy::Type::StatusCode::Forbidden }
  }.freeze

  def ok_response(req, service)
    Envoy::Service::Auth::V2::CheckResponse.new(
      status: Google::Rpc::Status.new(code: GRPC::Core::StatusCodes::OK),
      ok_response: Envoy::Service::Auth::V2::OkHttpResponse.new(
        headers: [
          # TODO: add headers
        ]
      )
    )
  end

  def denied_response(message, status: :forbidden)
    Envoy::Service::Auth::V2::CheckResponse.new(
      status: Google::Rpc::Status.new(code: RESPONSE_CODES.dig(status, :grpc)),
      denied_response: Envoy::Service::Auth::V2::DeniedHttpResponse.new(
        status: Envoy::Type::HttpStatus.new(code: RESPONSE_CODES.dig(status, :envoy)),
        body: message,
        headers: [
          Envoy::Api::V2::Core::HeaderValueOption.new(header: Envoy::Api::V2::Core::HeaderValue.new(key: 'x-ext-auth-reason', value: status.to_s)),
        ]
      )
    )
  end
end

require_relative 'auth_service/policy_registry'
require_relative 'auth_service/context'
