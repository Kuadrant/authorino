# frozen_string_literal: true

module UMA
  class Exception < StandardError; end

  class ValidationFailed < Exception
    attr_reader :object

    def initialize(object)
      super object.errors.full_messages.to_sentence
      @object = object
    end
  end
end
