# frozen_string_literal: true

require 'keycloak_adapter'

module Authentication
  extend ActiveSupport::Concern

  included do
    include SessionToken

    protected

    def authentication_required
      return if current_user
      redirect_to(authentication_server.authorize_url(redirect_uri: callback_url))
    end

    def current_user
      return unless jwt && authentication_server.token_valid?
      @current_user ||= jwt.first.slice('sub', 'email', 'name', 'preferred_username')
    end

    def authenticate!
      authentication_server.authenticate!(params[:code], redirect_uri: callback_url)
    end

    def create_session
      clear_session
      build_session
    end

    def refresh_session
      create_session if authentication_server.refresh_token!
    end

    def destroy_session
      clear_session
      redirect_to(authentication_server.logout_url(redirect_uri: root_url))
    end

    def access_token_jwt
      decode_jwt(stored_access_token)
    end

    alias jwt access_token_jwt

    def refresh_token_jwt
      decode_jwt(stored_refresh_token)
    end

    def id_token_jwt
      decode_jwt(stored_id_token)
    end

    helper_method :current_user, :access_token_jwt, :refresh_token_jwt, :id_token_jwt

    private

    def authentication_server_config
      Rails.application.config.keycloak.client
    end

    def authentication_server
      @authentication_server ||= KeycloakAdapter::Adapter.new(authentication_server_config, access_token: stored_access_token, refresh_token: stored_refresh_token)
    end

    TOKEN_REFERENCE_COOKIE_NAME = 'token_reference'

    def build_session
      token = authentication_server.token
      token_reference = token['session_state']
      store_token(token_reference, token)
      cookie_options = { expires: Time.at(token.expires_at), secure: false, httponly: false }
      cookies[TOKEN_REFERENCE_COOKIE_NAME] = { value: token_reference, **cookie_options }
    end

    def clear_session
      reset_session
      cookies.delete(TOKEN_REFERENCE_COOKIE_NAME)
    end

    def token_reference
      request.cookies[TOKEN_REFERENCE_COOKIE_NAME].presence
    end

      def decode_jwt(value)
      return unless value
      JWT.decode(value, nil, false)
    end
  end
end
