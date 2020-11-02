# frozen_string_literal: true

require_relative 'response'

class Config::Authorization::JWT < Config::Authorization
  def call(context)
    return unless enabled?

    # TODO: Build response
  end
end
