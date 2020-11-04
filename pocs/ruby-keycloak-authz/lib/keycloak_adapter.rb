# frozen_string_literal: true

module KeycloakAdapter
  class AuthorizationError < StandardError; end
  class MissingTokenError < AuthorizationError; end
end

Dir[Rails.root.join('lib', 'keycloak_adapter', '*.rb')].each { |file| require file }
