# frozen_string_literal: true

module KeycloakAdapter
  class ParsedJWT < Struct.new(:payload, :header)
  end
end
