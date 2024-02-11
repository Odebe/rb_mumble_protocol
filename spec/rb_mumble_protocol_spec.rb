# frozen_string_literal: true

RSpec.describe RbMumbleProtocol do
  it "has a version number" do
    expect(RbMumbleProtocol::VERSION).not_to be nil
  end

  describe "use cases" do
    let(:server_state) { RbMumbleProtocol::CryptState.new }
    let(:client_state) do
      # swap nonce vectors side to side
      RbMumbleProtocol::CryptState.new_from(
        server_state.key,
        server_state.decrypt_nonce,
        server_state.encrypt_nonce
      )
    end

    let(:bytes) { "test".bytes }

    describe "happy path" do
      let(:encrypted) { server_state.encrypt(bytes) }
      let(:decrypted) { client_state.decrypt(encrypted) }

      it { expect(decrypted.success?).to be_truthy }
      it { expect(decrypted.data).to eq(bytes) }
    end

    describe "errors" do
      let(:result) { client_state.decrypt(encrypted) }

      context "when repeat" do
        let(:encrypted) { server_state.encrypt(bytes) }

        before do
          client_state.decrypt(encrypted)
        end

        it "fails" do
          expect(result).to have_attributes('success?': false, reason: :repeat)
        end
      end

      context "when late" do
        let(:result) { client_state.decrypt(@first_message) }

        before do
          @first_message = server_state.encrypt(bytes)
          31.times { server_state.encrypt(bytes) }
        end

        it "fails" do
          expect(result).to have_attributes('success?': false, reason: :late)
        end
      end

      context "when encrypted is too short (< 4)" do
        let(:encrypted) { [1, 2, 3] }

        it "fails" do
          expect(result).to have_attributes('success?': false, reason: :eof)
        end
      end

      context "when crypto-attack" do

        let(:encrypted) do
          value = server_state.encrypt(bytes)
          # custom header from attacker
          value[1] = 2
          value[2] = 3
          value[3] = 69
          value
        end

        it "raises error" do
          expect(result).to have_attributes('success?': false, reason: :mac)
        end
      end
    end
  end
end
