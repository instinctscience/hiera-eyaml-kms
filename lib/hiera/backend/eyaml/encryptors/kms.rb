require 'openssl'
require 'hiera/backend/eyaml/encryptor'
require 'hiera/backend/eyaml/utils'
require 'hiera/backend/eyaml/options'
require 'aws-sdk-kms'

class Hiera
  module Backend
    module Eyaml
      module Encryptors

        class Kms < Encryptor
          # self.options = {
          #   :key_id => {      :desc => "KMS Key ID",
          #                     :type => :string,
          #                     :default => "" },
          # }
          # look up the KMS key id from a KMS alias being passed in
          # an environment variable
          self.options = {
            :key_alias => {
              :desc => "KMS Alias",
              :type => :string,
              :default => ENV['KMS_ALIAS'] || "helm" },
          }

          def self.kms_key_id
            @kms = ::Aws::KMS::Client.new()
            resp = @kms.list_aliases({
              # limit: 1
              # target_key_id: "string",
            })
            resp.aliases.each do |alias_obj|
              # puts "alias: #{alias_obj.alias_name}"
              # puts "target_key_id: #{alias_obj.target_key_id}"
              # print the default value of the object self.options[:key_alias]
              # puts "default: #{self.options[:key_alias][:default]}"
              if alias_obj.alias_name == "alias/#{self.options[:key_alias][:default]}"
                # puts "KMS key id: #{alias_obj.target_key_id}"
                return alias_obj.target_key_id
              end
            end
            return nil


          end

          # puts "KMS key id: #{self.kms_key_id}"

          VERSION = "0.5"
          self.tag = "KMS"

          def self.encrypt plaintext
            key_id = self.kms_key_id
            raise StandardError, "key_id is not defined" unless key_id

            @kms = ::Aws::KMS::Client.new()

            resp = @kms.encrypt({
              key_id: key_id,
              plaintext: plaintext
            })

            resp.ciphertext_blob
          end

          def self.decrypt ciphertext
            @kms = ::Aws::KMS::Client.new()

            resp = @kms.decrypt({
              ciphertext_blob: ciphertext
            })

            resp.plaintext
          end

        end

      end

    end

  end

end
