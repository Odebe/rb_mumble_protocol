# frozen_string_literal: true

require_relative "lib/rb_mumble_protocol/version"

Gem::Specification.new do |spec|
  spec.name = "rb_mumble_protocol"
  spec.version = RbMumbleProtocol::VERSION
  spec.authors = ["Mikhail Odebe"]
  spec.email = ["derpiranha@gmail.com"]

  spec.summary = "Gem that providing classes for implementing Mumble-related projects."
  spec.description = "Gem that providing classes for implementing Mumble-related projects."
  spec.homepage = "https://github.com/Odebe/rb_mumble_protocol"
  spec.required_ruby_version = ">= 2.6.0"
  spec.required_rubygems_version = ">= 3.3.11"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = spec.homepage

  spec.files =
    Dir["lib/**/*.rb"]
      .concat(Dir["ext/rb_mumble_protocol/src/**/*.rs"]) <<
        "ext/rb_mumble_protocol/Cargo.toml" << "Cargo.toml" << "Cargo.lock"

  spec.require_paths = ["lib"]
  spec.extensions = ["ext/rb_mumble_protocol/Cargo.toml"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
