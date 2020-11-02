# frozen_string_literal: true

class SessionsController < ApplicationController
  include Authentication

  before_action :authentication_required, except: %i[create destroy]

  def show; end

  def create
    return render(:nothing, status: :forbidden) unless authenticate!
    create_session
    flash[:notice] = 'Session created'
    redirect_to session_path
  end

  def update
    flash[:notice] = refresh_session ? 'Token refreshed' : 'Token still fresh'
    redirect_to session_path
  end

  def destroy
    destroy_session
  end

  alias new destroy
end
