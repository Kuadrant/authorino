# frozen_string_literal: true

class Config::Authorization < OpenStruct
  extend Config::BuildSubclass

  def enabled?
    enabled.nil? || !!enabled
  end
end

require_relative 'authorization/opa'
require_relative 'authorization/jwt'
