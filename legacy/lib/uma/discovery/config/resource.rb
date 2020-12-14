# frozen_string_literal: true

require 'openssl'

module UMA
  module Discovery
    class Config
      class Resource < OpenIDConnect::Discovery::Provider::Config::Resource
        undef_required_attributes :principal, :service

        def initialize(uri)
          @scheme = uri.scheme
          @host = uri.host
          @port = uri.port unless [80, 443].include?(uri.port)
          @path = File.join uri.path, '.well-known/uma2-configuration'
          attr_missing!
        end

        private

        def to_response_object(hash)
          Response.new(hash)
        end

        def cache_key
          sha256 = OpenSSL::Digest::SHA256.hexdigest host
          "swd:resource:uma2-conf:#{sha256}"
        end
      end
    end
  end
end
