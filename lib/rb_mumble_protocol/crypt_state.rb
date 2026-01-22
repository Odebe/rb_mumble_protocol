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

  class DecryptResult
    REASONS = {
      0 => :ok,
      1 => :repeat,
      2 => :late,
      3 => :mac,
      4 => :eof
    }.freeze

    def reason
      REASONS[reason_raw_value]
    end
  end
end
