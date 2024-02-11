# frozen_string_literal: true

module RbMumbleProtocol
  class CryptState
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
