# frozen_string_literal: true

require 'net/http'
require 'json'

class Config::Metadata::UserInfo < Config::Metadata
  def call(context)
    identity_finder = Config::Identity::OIDC[self[:oidc]]
    identity = context.service.identity.find { |identity| identity_finder === identity } or return
    token_id = context.identity.fetch(identity) { return }

    oidc_config = identity.config
    uri = URI(oidc_config.token_introspection_endpoint || oidc_config.introspection_endpoint)
    uri.user = client_id
    uri.password = client_secret

    response = Net::HTTP.post_form(uri, { 'token' => token_id, 'token_type_hint' => 'requesting_party_token' })

    case response
    when Net::HTTPOK
      case response['content-type']
      when 'application/json'
        JSON.parse(response.body)
      end
    end
  end
end
