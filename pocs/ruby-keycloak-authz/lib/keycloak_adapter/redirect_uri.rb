# frozen_string_literal: true

module KeycloakAdapter
  class RedirectUri
    NOT_ALLOWED_PARAMS = %w[code].freeze

    def self.call(*args)
      new(*args).call
    end

    def initialize(request)
      @uri = URI(request.url)
      @request = request
    end

    attr_reader :uri, :request

    def call
      clean_query_params
      add_host
      uri.to_s
    end

    protected

    def clean_query_params
      uri.query = parsed_query_params.except(*NOT_ALLOWED_PARAMS).to_query.presence
    end

    def parsed_query_params
      Rack::Utils.parse_query(@uri.query)
    end

    def add_host
      uri.host = request.host
    end
  end
end
