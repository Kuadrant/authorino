# frozen_string_literal: true

require 'yaml/store'
require 'ostruct'

class Config
  def initialize(file)
    @store = YAML::Store.new(file)
  end

  def for_host(name)
    @store.transaction(true) do
      case (service = @store.fetch(name, Service::NotFound))
      when Service::NotFound
        Service::NotFound
      else
        Service.new(service)
      end
    end
  end

  def host_names
    @store.transaction(true) { @store.roots }
  end

  def each_host(&block)
    host_names.map(&method(:for_host)).map(&block)
  end

  module BuildSubclass
    class AmbiguousKeysError < StandardError; end

    def build(object)
      name = object.keys.tap { |keys| raise AmbiguousKeysError, keys if keys.size > 1 }.first
      const = constants(false).find { |const| const.to_s.downcase == name.to_s.downcase }
      const_get(const, false).new(object.fetch(name))
    end
  end
end

require_relative 'config/discoverable'
require_relative 'config/service'
require_relative 'config/identity'
require_relative 'config/authorization'
require_relative 'config/metadata'
