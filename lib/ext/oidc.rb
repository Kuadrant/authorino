# frozen_string_literal: true

require 'openid_connect'

Module.new do
  ### Monkey patch to keep the desired scheme of the issuer instead forcing it into https

  def initialize(uri)
    @scheme = uri.scheme
    super
  end

  attr_reader :scheme

  def endpoint
    URI::Generic.build(scheme: scheme, host: host, port: port, path: path)
  rescue URI::Error => e
    raise SWD::Exception.new(e.message)
  end

  prepend_features(::OpenIDConnect::Discovery::Provider::Config::Resource)
end

# not in the RFC, but keycloak has it
OpenIDConnect::Discovery::Provider::Config::Response.attr_optional :token_introspection_endpoint, :introspection_endpoint
OpenIDConnect::ResponseObject::IdToken.attr_optional :realm_access, :resource_access, :scope, :email_verified, :preferred_username, :email

