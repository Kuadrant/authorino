# frozen_string_literal: true

require 'json'
require 'securerandom'

class RackApp
  def call(env)
    request = Rack::Request.new(env)
    request_method = request.request_method
    request_path = request.path
    request_query_string = request.query_string
    request_query_string = nil if request_query_string.empty?
    request_headers = env.select { |header, _| header.start_with?('HTTP_') || header == 'CONTENT_LENGTH' || header == 'CONTENT_TYPE' }
    response_status = request_headers['HTTP_X_ECHO_STATUS']&.to_i || 200
    response_message = request_headers['HTTP_X_ECHO_MESSAGE']
    response_content_type = response_message ? 'text/plain' : 'application/json'
    response_message ||= JSON.pretty_generate(
      method: request_method,
      path: request_path,
      query_string: request_query_string,
      body: request.body.read,
      headers: request_headers,
      uuid: SecureRandom.uuid
    )

    puts "[#{Time.now}] #{request_method} #{[request_path, request_query_string].compact.join('?')} => #{response_status}"

    [response_status, { 'Content-Type' => response_content_type }, [response_message]]
  end
end

run RackApp.new
