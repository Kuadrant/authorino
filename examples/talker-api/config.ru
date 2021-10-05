# frozen_string_literal: true

require 'json'
require 'securerandom'
require 'net/http/status'

class RackApp
  def call(env)
    request = Rack::Request.new(env)
    request_method = request.request_method
    request_path = request.path
    request_query_string = request.query_string
    request_query_string = nil if request_query_string.empty?
    request_status_line = "#{request_method} #{[request_path, request_query_string].compact.join('?')}"
    request_headers = env.select { |header, _| header.start_with?('HTTP_') || header == 'CONTENT_LENGTH' || header == 'CONTENT_TYPE' }.transform_keys { |header| header.sub(/^HTTP_/, '').split('_').map(&:capitalize).join('-') }
    request_version = request_headers['Version']
    request_body = request.body.read

    response_status = request_headers['X-Echo-Status']&.to_i || 200
    response_message = Net::HTTP::STATUS_CODES[response_status]
    response_body = request_headers['X-Echo-Message']
    response_content_type = response_body ? 'text/plain' : 'application/json'
    response_headers = { 'Content-Type' => response_content_type }
    response_body ||= JSON.pretty_generate(
      method: request_method,
      path: request_path,
      query_string: request_query_string,
      body: request_body,
      headers: request_headers,
      uuid: SecureRandom.uuid
    )

    log_details = if ENV['LOG_LEVEL'].to_s.downcase == 'debug'
      [
        '',
        '[Request]',
        "#{request_status_line} #{request_version}",
        request_headers.map{ |k,v| [k, v].join(': ') },
        '(…request headers omitted)',
        '',
        request_body,
        '',
        '[Response]',
        "#{request_version} #{response_status} #{response_message}",
        response_headers.map{ |k,v| [k, v].join(': ') },
        '(…response headers omitted)',
        '',
        response_body,
      ].flatten.map(&method(:indent)).join("\n")
    else
      "=> #{response_status}"
    end

    puts "[#{Time.now}] #{request_status_line} #{log_details}"

    [response_status, response_headers, [response_body]]
  end

  protected

  def indent(str)
    ['  ', str].join
  end
end

run RackApp.new
