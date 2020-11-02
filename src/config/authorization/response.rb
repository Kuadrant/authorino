# frozen_string_literal: true

class Config::Authorization::Response < OpenStruct
  def authorized?
    raise NotImplementedError, __method__
  end
end
