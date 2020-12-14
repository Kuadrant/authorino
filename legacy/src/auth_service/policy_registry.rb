# frozen_string_literal: true

class AuthService::PolicyRegistry
  def self.setup!(config)
    new(config).setup!
  end

  def initialize(config)
    @config = config
  end

  attr_reader :config

  def setup!
    config.each_host.flat_map(&:authorization).map do |authorization|
      authorization.try(:register!)
    end
  end
end
