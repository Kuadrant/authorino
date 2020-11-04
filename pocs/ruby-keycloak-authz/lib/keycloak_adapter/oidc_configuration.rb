# frozen_string_literal: true

module KeycloakAdapter
  class OidcConfiguration
    def initialize(issuer:, **opts)
      @issuer = issuer
      @options = ActiveSupport::OrderedOptions.new.merge(opts)
      @configuration = ActiveSupport::OrderedOptions.new.merge(fetch_configuration.symbolize_keys)
      @certs = fetch_certs.deep_symbolize_keys
    ensure
      connection&.close
    end

    attr_reader :issuer, :certs
    delegate :authorization_endpoint, :token_endpoint, :introspection_endpoint, :userinfo_endpoint, :end_session_endpoint, to: :configuration

    def to_h
      configuration.to_h
    end

    protected

    attr_reader :options, :configuration

    def fetch_configuration
      fetch_json(options.discovery_path)
    end

    def fetch_certs
      fetch_json(options.certs_path)
    end

    def connection
      @connection ||= Faraday.new(issuer, options.connection_options)
    end

    def fetch_json(path)
      response = connection.get(path) do |request|
        request.headers = { 'Content-Type' => 'application/json; charset=utf-8' }
      end

      JSON.parse(response.body)
    end
  end
end
