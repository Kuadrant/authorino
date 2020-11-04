# frozen_string_literal: true

class AuthService::Context
  attr_reader :identity, :metadata, :authorization
  attr_reader :request, :service

  def initialize(request, service)
    @request = request
    @service = service
    @identity = {}
    @metadata = {}
    @authorization = {}
  end

  def evaluate!
    proc = ->(obj, result) { result[obj] = obj.call(self) }

    service.identity.each_with_object(identity, &proc)
    service.metadata.each_with_object(metadata, &proc)
    service.authorization.each_with_object(authorization, &proc)

    @identity.freeze
    @metadata.freeze
    @authorization.freeze
  end

  def authenticated?
    identity.values.any?
  end

  def authorized?
    authorization.select { |config, _| config.enabled? }.values.all?(&:authorized?)
  end

  def valid?
    authenticated? && authorized?
  end

  def to_h
    {
      request: request,
      service: service,
      identity: identity.transform_keys(&:name).transform_values{ |value| value.try(:to_h) },
      metadata: metadata.transform_keys{ |key| key.class.to_s.demodulize.underscore }
    }.transform_values(&:to_h)
  end
end
