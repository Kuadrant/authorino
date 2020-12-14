# frozen_string_literal: true

require 'test_helper'
require 'json'

describe AuthService do
  let(:config) { Config.new(file_fixture('config.yml')) }
  let(:service) { AuthService.new(config) }

  describe 'request' do
    let(:body) { JSON.parse(file_fixture('request.json').read) }
    let(:request) { Envoy::Service::Auth::V2::CheckRequest.decode_json body.to_json }

    subject do
      service.check(request, GRPC::ActiveCall.allocate)
    end

    it 'must respond positively' do
      expect(subject).must_be_instance_of(Envoy::Service::Auth::V2::CheckResponse)
      expect(subject.ok_response).must_be_instance_of(Envoy::Service::Auth::V2::OkHttpResponse)
    end
  end
end
