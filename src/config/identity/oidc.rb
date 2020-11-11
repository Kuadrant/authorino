# frozen_string_literal: true

require 'ext/oidc'

class Config::Identity::OIDC < Config::Identity
  include Config::Discoverable

  def discover!
    raise OpenIDConnect::Discovery::DiscoveryFailed unless endpoint

    self[:config] ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(endpoint)
  rescue OpenIDConnect::Discovery::DiscoveryFailed => err
    GRPC.logger.debug("OIDC discovery failed: #{err}")
    self.enabled = false
    nil
  end

  class Token
    def initialize(token)
      @token = token
    end

    def decode!(keys)
      @decoded = ::OpenIDConnect::ResponseObject::IdToken.decode(@token, keys)
    end

    def to_s
      @token
    end

    delegate :raw_attributes, to: :@decoded, allow_nil: true
    alias to_h raw_attributes # because OpenIDConnect::ResponseObject::IdToken#as_json will only return string values

    private def method_missing(symbol, *args, &block)
      return super unless @decoded
      @decoded.public_send(symbol, *args, &block)
    end
  end

  def call(context)
    request = context.request
    id_token = decode_id_token(request)
  rescue JSON::JWK::Set::KidNotFound, JSON::JWS::VerificationFailed => err
    GRPC.logger.debug("Failed to decode JWT: #{err}")
    false
  end

  def decode_id_token(req)
    auth = Rack::Auth::AbstractRequest.new(req.attributes.request.http.to_env)

    case auth.scheme
    when 'bearer'
      Token.new(auth.params).tap { |t| t.decode!(public_keys) }
    end
  end

  def public_keys
    config&.jwks
  end
end
