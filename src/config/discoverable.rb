# frozen_string_literal: true

class Config
  module Discoverable
    def config
      case config = self[:config]
      when nil
        discover!
      when Hash
        self[:config] = OpenStruct.new(config)
      else
        config
      end
    end
  end
end
