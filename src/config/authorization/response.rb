# frozen_string_literal: true

class Config::Authorization::Response < OpenStruct
  def authorized?
    raise NotImplementedError, __method__
  end

  class Authorized < self
    def authorized?
      true
    end
  end

  class Unauthorized < self
    def authorized?
      false
    end
  end
end
