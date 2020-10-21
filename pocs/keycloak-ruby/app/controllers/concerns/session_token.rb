# frozen_string_literal: true

module SessionToken
  def store_token(token_reference, token)
    session[token_reference] = {
      access_token: token.token,
      refresh_token: token.refresh_token,
      id_token: token['id_token']
    }
  end

  def stored_token(token_reference = self.token_reference)
    session[token_reference] || {}
  end

  def stored_access_token
    stored_token[:access_token]
  end

  def stored_refresh_token
    stored_token[:refresh_token]
  end

  def stored_id_token
    stored_token[:id_token]
  end
end
