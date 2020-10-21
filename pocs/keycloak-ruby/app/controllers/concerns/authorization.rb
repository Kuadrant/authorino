# frozen_string_literal: true

module Authorization
  extend ActiveSupport::Concern

  included do
    include SessionToken

    class_attribute :resource_name

    protected

    SCOPES = {
      view: %i[show index],
      create: %i[new create],
      delete: :delete
    }

    def authorize!
      permission = [resource_name, authorization_scope].join('#')
      authorizarion_server.authorize!(permission: permission)
    rescue KeycloakAdapter::AuthorizationError => exception
      flash[:error] = exception.message.humanize
      redirect_to on_deny_redirect_to
    end

    private

    def authorization_server_config
      Rails.application.config.keycloak.resource_server
    end

    def authorizarion_server
      @authorizarion_server ||= KeycloakAdapter::Adapter.new(authorization_server_config, access_token: authorization_token)
    end

    def authorization_token
      ActionController::HttpAuthentication::Token.token_and_options(request)&.first || stored_access_token
    end

    def resource_name
      self.class.resource_name || (self.class.name.demodulize.sub(/Controller$/, '').singularize)
    end

    def authorization_scope
      SCOPES.find { |_, values| [*values].include?(action_name.to_sym) }&.first
    end

    def on_deny_redirect_to
      authorization_server_config.dig(:'policy-enforcer', :'on-deny-redirect-to') || root_path
    end
  end
end
