# frozen_string_literal: true

require 'minitest/autorun'
require 'pathname'

root = Pathname(__dir__).expand_path.dirname

%w[lib lib/grpc src].each do |path|
  $LOAD_PATH << root.join(path)
end

Module.new do
  def file_fixture(filename)
    Pathname.new(File.join(__dir__, "fixtures/#{filename}"))
  end

  prepend_features(Minitest::Spec)
end

require 'main'
