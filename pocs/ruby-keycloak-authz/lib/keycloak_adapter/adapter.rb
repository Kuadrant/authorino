# frozen_string_literal: true

require 'oauth2'

module KeycloakAdapter
  class Adapter
    # TODO: Make this configurable
    DEFAULT_OPTIONS = {
      discovery_path: '.well-known/openid-configuration',
      certs_path: 'protocol/openid-connect/certs',
      connection_options: { ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE } }
    }.freeze

    DEFAULT_AUTHZ_REQUEST_OPTIONS = {
      body: {
        grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
        response_mode: 'decision'
      },
      raise_errors: false
    }.freeze

    def initialize(server_config, **opts)
      uri = URI.parse(server_config['auth-server-url'])
      uri.path += ['realms', server_config['realm']].join('/')
      @issuer = uri.to_s
      @client_id = server_config['resource']
      @client_secret = server_config.dig('credentials', 'secret')
      @options = ActiveSupport::OrderedOptions.new.merge(opts.symbolize_keys.reverse_merge(DEFAULT_OPTIONS))
    end

    attr_reader :issuer, :client_id, :client_secret, :options

    delegate :redirect_uri, :redirect_uri=, to: :options

    def authorize_url(redirect_uri: self.redirect_uri)
      oauth_client.auth_code.authorize_url(request_code_options.merge(redirect_uri: redirect_uri))
    end

    def authenticate!(authorization_code, redirect_uri: self.redirect_uri)
      @token ||= oauth_client.auth_code.get_token(authorization_code, get_token_options.merge(redirect_uri: redirect_uri))
    end

    def authorize!(params = {})
      raise MissingTokenError unless token
      request_options = DEFAULT_AUTHZ_REQUEST_OPTIONS.deep_merge(body: params.reverse_merge(audience: client_id))
      response = token.post(oidc_configuration.token_endpoint, **request_options)
      parsed_response = response.parsed
      raise AuthorizationError.new(parsed_response['error_description'] || parsed_response['error']) if response.status >= 300
    end

    def token
      return if preloaded_token_options.blank?
      @token ||= OAuth2::AccessToken.from_hash(oauth_client, preloaded_token_options)
    end

    def jwt
      return unless token
      ParsedJWT.new(*JWT.decode(token.token, nil, false))
    end

    def token_valid?
      validate_token && !token.expired?
    end

    def validate_token
      return unless token
      decode_options = {
        algorithm: jwt.header['alg'],
        verify_iat: true,
        verify_aud: true,
        jwks: oidc_configuration.certs
      }
      JWT.decode(token.token, nil, true, decode_options)
    end

    def refresh_token!
      @token = token.refresh!
    end

    def user_info
      return unless token
      token.get(oidc_configuration.userinfo_endpoint).parsed.presence
    end

    def logout_url(redirect_uri: self.redirect_uri)
      uri = URI(oidc_configuration.end_session_endpoint)
      uri.query = auth_code_options.merge(redirect_uri: redirect_uri).to_param
      uri.to_s
    end

    def scopes
      'openid'
    end

    protected

    def oidc_configuration_cache
      @@oidc_configuration_cache ||= {}
    end

    def build_oidc_configuration
      OidcConfiguration.new(issuer: issuer, **options.slice(:discovery_path, :certs_path, :connection_options))
    end

    def oidc_configuration
      oidc_configuration_cache[issuer] || @@oidc_configuration_cache[issuer] = build_oidc_configuration
    end

    def oauth_client
      @oauth_client ||= OAuth2::Client.new(client_id, client_secret, client_options)
    end

    def client_options
      {
        site: issuer,
        realm: issuer,
        authorize_url: oidc_configuration.authorization_endpoint,
        token_url: oidc_configuration.token_endpoint,
        connection_opts: options.connection_options,
        auth_scheme: :request_body
      }
    end

    def auth_code_options
      { redirect_uri: redirect_uri }
    end

    def request_code_options
      auth_code_options.merge(scope: scopes)
    end

    alias get_token_options auth_code_options

    def preloaded_token_options
      options.slice(:access_token, :refresh_token)
    end
  end
end
