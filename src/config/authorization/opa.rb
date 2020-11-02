# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

require_relative 'response'

class Config::Authorization::OPA < Config::Authorization
  DEFAULTS = {
    endpoint: 'http://localhost:8181',
    data_api: '/v1/data/ostia/authz',
    policy_api: '/v1/policies'
  }

  class Response < Config::Authorization::Response
    def authorized?
      result['allow']
    end
  end

  class RegisterException < StandardError; end

  def register!
    auth_request = Net::HTTP::Put.new(policy_uri, 'Content-Type' => 'text/plain')
    auth_request.body = rego_policy
    auth_response = Net::HTTP.start(policy_uri.hostname, policy_uri.port) do |http|
      http.request(auth_request)
    end

    case auth_response
    when Net::HTTPOK
      JSON.parse(auth_response.body)
    else
      raise RegisterException, auth_response
    end
  rescue RegisterException, Net::HTTPError
    self.enabled = false
    nil
  end

  def call(context)
    return unless enabled?

    auth_request = Net::HTTP::Post.new(data_uri, 'Content-Type' => 'application/json')
    request, identity, metadata = context.to_h.values_at(:request, :identity, :metadata)
    auth_request.body = { input: request.merge(context: { identity: identity.values.first, metadata: metadata }) }.to_json
    puts "[OPA] #{auth_request.body}"
    auth_response = Net::HTTP.start(data_uri.hostname, data_uri.port) do |http|
      http.request(auth_request)
    end

    case auth_response
    when Net::HTTPOK
      response_json = case auth_response['content-type']
                      when 'application/json'
                        JSON.parse(auth_response.body)
                      else
                        { allowed: true, message: auth_response.body }
                      end
      Response.new(response_json)
    end
  end

  protected

  DEFAULTS.keys.each do |attribute|
    define_method(attribute) do
      super() || DEFAULTS[attribute]
    end
  end

  alias _endpoint endpoint

  def endpoint
    URI.parse(_endpoint)
  end

  def data_uri
    uri = endpoint
    uri.path = [data_api, uuid].join('/')
    uri
  end

  def policy_uri
    uri = endpoint
    uri.path = [policy_api, uuid].join('/')
    uri
  end

  def rego_policy
    <<~REGO
      package ostia.authz["#{uuid}"]

      import input.attributes.request.http as http_request
      import input.context.identity
      import input.context.metadata

      resource = object.get(input.context, "resource", {})
      path = split(trim_left(http_request.path, "/"), "/")

      default allow = false

      #{rego}
    REGO
  end
end
