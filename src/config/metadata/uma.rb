# frozen_string_literal: true

require 'uma'

class Config::Metadata::UMA < Config::Metadata
  class Error < StandardError; end
  class TokenError < Error; end
  class ResourceError < Error; end

  include Config::Discoverable

  DiscoveryFailed = ::UMA::Discovery::DiscoveryFailed

  def discover!
    raise DiscoveryFailed unless endpoint

    self[:config] ||= ::UMA::Discovery::Config.discover!(endpoint)
  rescue DiscoveryFailed => err
    error("[UMA] discovery failed: #{err}")
    self.enabled = false
    nil
  end

  def call(context)
    # get the protection API token (PAT)
    token_uri = client_authenticated_uri(config.token_endpoint)
    token_response = Net::HTTP.post_form(token_uri, { 'grant_type' => 'client_credentials' })
    raise TokenError, token_response unless Net::HTTPOK === token_response
    pat = JSON.parse(token_response.body)['access_token']

    uma_request_headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{pat}" }

    # query resources by URI
    resource_uri = URI.parse(config.resource_registration_endpoint)
    resource_uri.query = resource_query = "uri=#{context.request.attributes.request.http.path}"
    resource_response = Net::HTTP.start(resource_uri.host, resource_uri.port) { |http| http.get(resource_uri, uma_request_headers) }
    raise ResourceError, resource_response unless Net::HTTPOK === resource_response
    resource_ids = JSON.parse(resource_response.body)
    resource_ids.any? or debug('[UMA] no resources found') && return

    # fetch resource data
    resource_uri.query = ''
    resource_ids.map do |resource_id|
      resource_uri.path += "/#{resource_id}"
      response = Net::HTTP.start(resource_uri.host, resource_uri.port) { |http| http.get(resource_uri, uma_request_headers) }
      resource_data = JSON.parse(response.body)
      debug("[UMA] resource data #{resource_data}")
      resource_data
    end
  rescue Net::HTTPError, Error => err
    error("[UMA] Failed to fetch resource data: #{err}")
  end

  protected

  delegate :debug, :error, to: 'GRPC.logger'

  def client_authenticated_uri(endpoint)
    uri = URI(endpoint)
    uri.user = client_id
    uri.password = client_secret
    uri
  end
end
