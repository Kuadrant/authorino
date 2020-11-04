# frozen_string_literal: true

class ResponseInterceptor < GRPC::ServerInterceptor
  def request_response(request:, call:, method:)
    GRPC.logger.info("Received request/response call at method #{method}" \
      " with request #{request} for call #{call}")

    GRPC.logger.info("[GRPC::Ok] (#{method.owner.name}.#{method.name})")
    yield
  end
end
