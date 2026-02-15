# frozen_string_literal: true

module RbMumbleProtocol
  class CryptState
    # swapping nonce vectors side to side
    def self.new_from(old_state)
      new(
        key: old_state.key,
        decrypt_nonce: old_state.encrypt_nonce,
        encrypt_nonce: old_state.decrypt_nonce
      )
    end
  end
end
