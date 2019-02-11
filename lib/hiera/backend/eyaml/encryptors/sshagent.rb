require 'base64'
require 'json'
require 'socket'
require 'stringio'

require 'fernet'

class Hiera
  module Backend
    module Eyaml
      module Encryptors
        class SSHAgent < Encryptor
          self.tag = 'SSHAGENT'

          SSH2_AGENTC_REQUEST_IDENTITIES = "\x0b".freeze
          SSH2_AGENT_IDENTITIES_ANSWER = "\x0c".freeze
          SSH2_AGENTC_SIGN_REQUEST = "\x0d".freeze
          SSH2_AGENT_SIGN_RESPONSE = "\x0e".freeze

          def self.read_u32(sock)
            sock.read(4).unpack('L>')[0]
          end

          def self.read_s(sock)
            sock.read(read_u32(sock))
          end

          def self.encode_s(str)
            [str.size].pack('I>') + str
          end

          def self.sign(sock, key_blob, challenge)
            request = (
              SSH2_AGENTC_SIGN_REQUEST +
              encode_s(key_blob) +
              encode_s(challenge) +
              [0].pack('L>')
            )
            sock.write(encode_s(request))

            sio = StringIO.new(read_s(sock))
            if sio.read(1) != SSH2_AGENT_SIGN_RESPONSE
              raise 'Expected SSH2_AGENT_SIGN_RESPONSE'
            end

            sio = StringIO.new(read_s(sio))
            raise 'Expected ssh-rsa' if read_s(sio) != 'ssh-rsa'

            read_s(sio)
          end

          def self.get_key_blob(sock, keyid)
            sock.write(encode_s(SSH2_AGENTC_REQUEST_IDENTITIES))

            sio = StringIO.new(read_s(sock))
            if sio.read(1) != SSH2_AGENT_IDENTITIES_ANSWER
              raise 'expected SSH2_AGENT_IDENTITIES_ANSWER'
            end

            (0...read_u32(sio)).each do
              key_blob = read_s(sio)
              key_comment = read_s(sio)
              break key_blob if key_comment == keyid
            end
          end

          class Encrypted
            attr_reader :challenge
            attr_reader :salt
            attr_reader :payload

            def initialize(challenge, salt, payload)
              @challenge = challenge
              @salt = salt
              @payload = payload
            end

            def to_dct
              {
                'challenge' => Base64.strict_encode64(@challenge),
                'salt' => Base64.strict_encode64(@salt),
                'payload' => @payload
              }
            end

            def self.from_dct(dct)
              Encrypted.new(
                Base64.decode64(dct['challenge']),
                Base64.decode64(dct['salt']),
                dct['payload']
              )
            end
          end

          def self.get_key(keyid, challenge, salt)
            signature_blob = Socket.unix(ENV['SSH_AUTH_SOCK']) do |sock|
              key_blob = get_key_blob(sock, keyid)
              break sign(sock, key_blob, challenge)
            end

            kdf = OpenSSL::PKCS5.pbkdf2_hmac(
              signature_blob,
              salt,
              100_000,
              32,
              OpenSSL::Digest::SHA256.new
            )
            Base64.encode64(kdf)
          end

          def self.encrypt_contents(keyid, contents)
            challenge = Random.urandom(64)
            salt = Random.urandom(16)
            key = get_key(keyid, challenge, salt)
            Encrypted.new(challenge, salt, Fernet.generate(key, contents))
          end

          def self.decrypt_contents(keyid, contents)
            enc = Encrypted.from_dct(JSON.parse(contents))
            key = get_key(keyid, enc.challenge, enc.salt)
            Fernet.verifier(key, enc.payload, enforce_ttl: false).message
          end

          self.options = {
            keyid: {
              desc: 'Key location -- it is the file path from `ssh-add -l`',
              type: :string
            }
          }

          def self.keyid
            keyid = option :keyid
            if keyid.nil? || keyid.empty?
              raise ArgumentError, 'No keyid configured!'
            end

            keyid
          end

          def self.encrypt(plaintext)
            enc = encrypt_contents(keyid, plaintext)
            JSON.generate(enc.to_dct)
          end

          def self.decrypt(ciphertext)
            decrypt_contents(keyid, ciphertext)
          end

          def self.create_keys
            STDERR.puts 'This encryptor does not support creation of keys'
          end
        end
      end
    end
  end
end
