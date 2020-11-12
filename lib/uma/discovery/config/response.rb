# frozen_string_literal: true

require 'openid_connect'

module UMA
  module Discovery
    class Config
      class Response < OpenIDConnect::Discovery::Provider::Config::Response
        unavailable_attributes = %i[subject_types_supported id_token_signing_alg_values_supported]
        undef_required_attributes(*unavailable_attributes)
        _validators.transform_values! do |validators|
          validators.map { |validator| unavailable_attributes.each(&validator.attributes.method(:delete)); validator }
        end

        uma_uri_attributes = {
          required: [
            :resource_registration_endpoint,
            :permission_endpoint,
            :policy_endpoint
          ],
          optional: []
        }
        attr_required(*uma_uri_attributes[:required])
      end
    end
  end
end
