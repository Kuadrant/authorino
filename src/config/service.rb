# frozen_string_literal: true

class Config::Service < OpenStruct
  NotFound = Object.new

  def initialize(hash = nil)
    super

    self.identity = Array(identity).map(&Config::Identity.method(:build))
    self.authorization = Array(authorization).map(&Config::Authorization.method(:build))
    self.metadata = Array(metadata).map(&Config::Metadata.method(:build))
  end

  def enabled?
    !!enabled
  end
end

require_relative 'identity'
require_relative 'authorization'
require_relative 'metadata'
