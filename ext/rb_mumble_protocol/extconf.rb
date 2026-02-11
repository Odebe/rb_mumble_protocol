# frozen_string_literal: true

require "mkmf"
require "rb_sys/mkmf"

create_rust_makefile("rb_mumble_protocol/rb_mumble_protocol") do |config|
  config.profile = :release
end
