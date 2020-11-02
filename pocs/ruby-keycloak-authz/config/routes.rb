# frozen_string_literal: true

Rails.application.routes.draw do
  resource :session, except: %i[index edit]
  get 'auth/callback', to: 'sessions#create', as: 'callback'
  get '/logout', to: 'sessions#destroy', as: 'logout'

  namespace :api do
    resources :services
  end

  root to: 'sessions#show'
end
