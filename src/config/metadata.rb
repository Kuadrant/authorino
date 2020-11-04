# frozen_string_literal: true

class Config::Metadata < OpenStruct
  extend Config::BuildSubclass
end

require_relative 'metadata/user_info'
