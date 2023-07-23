# RbMumbleProtocol
Ruby gem that providing classes for implementing Mumble-related projects.

Not quite a bindings for Rust crate, but kinda a fork of [rust-mumble-protocol crate](https://github.com/Johni0702/rust-mumble-protocol/tree/master).

## Why?
[rust-mumble-protocol](https://github.com/Johni0702/rust-mumble-protocol/tree/master) has strong coupling between CryptState and Codec (packets decoder).
In my case I needed CryptState that takes encrypted bytes, returns decrypted bytes and holds some statistics.

## Roadmap
- [x] CryptState
- [ ] Stream wrapper (varint r/w)
- [ ] Protobuf/Voice Packets decoder

## Installation
Install the gem and add to the application's Gemfile by executing:

    $ bundle add rb_mumble_protocol

If bundler is not being used to manage dependencies, install the gem by executing:

    $ gem install rb_mumble_protocol

## Usage

TODO: Write usage instructions here

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/rb_mumble_protocol.
