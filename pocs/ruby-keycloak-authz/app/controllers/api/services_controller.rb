# frozen_string_literal: true

require 'securerandom'

module Api
  class ServicesController < ApplicationController
    Service = Struct.new(:id, :name, :description)

    include Authentication
    include Authorization

    before_action :authentication_required
    before_action :authorize!
    before_action :find_service, only: %i[show destroy]

    def new; end

    def create
      @service = build_fake_service
      flash[:notice] = "Service #{@service.id} successfully created"
      redirect_to api_service_path(@service.id)
    end

    def index
      @services = collection
    end

    def show; end

    def destroy
      flash[:notice] = "Service #{@service.id} successfully deleted"
      redirect_to api_services_path
    end

    protected

    def collection
      [Service.new('b1923272-6578-47de-82f5-31da55891ae3', 'Fake service', 'Service to test Keycloak with Ruby')]
    end

    def build_fake_service
      Service.new(params[:id] || SecureRandom.uuid, "Sorry, we didn't really save this", "Sorry, we didn't really save this")
    end

    def find_service
      @service = collection.find { |service| service.id == params[:id] } || build_fake_service
    end
  end
end
