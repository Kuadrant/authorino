# frozen_string_literal: true

desc "Generates the code that implements the gRPC protocol for Envoy's ext_authz filter"
task :generate do
  include_packages = %w[googleapis protoc-gen-validate data-plane-api udpa]
  include_packages_args = include_packages.map { |package| "-I./vendor/envoy-xds-grpc/#{package}" }.join(' ')
  sh "grpc_tools_ruby_protoc #{include_packages_args} @./vendor/envoy-xds-grpc/protos --ruby_out=lib/grpc --grpc_out=lib/grpc"
end

task default: %i[generate start]

desc 'Runs the application'
task :start do
  ruby "-Ilib -Ilib/grpc -Isrc src/main.rb"
end

desc 'Loads the application source'
task :app do
  $LOAD_PATH << 'src' << 'lib' << 'lib/grpc'
  require 'main'
end

desc 'Launches a console with the application source loaded'
task console: %i[app] do
  require 'pry'
  Pry.start
end

desc 'Run the tests'
task :test do |_task, test_files|
  files = test_files.to_a.flat_map(&:split)
  files = Dir['test/**/*_test.rb'] if files.empty?
  files.each do |file|
    puts "Running test #{file}"
    ruby "-Ilib -Ilib/grpc -Itest -Isrc #{file}"
  end
end
