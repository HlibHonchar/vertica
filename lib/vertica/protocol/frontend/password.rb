module Vertica
  module Protocol
    class Password < FrontendMessage
      message_id 'p'

      def initialize(password, auth_method: Vertica::Protocol::Authentication::CLEARTEXT_PASSWORD, salt: nil, user: nil, usersalt: nil)
        @password = password
        @auth_method, @salt, @user, @usersalt = auth_method, salt, user, usersalt
      end

      def encoded_password
        case @auth_method
        when Vertica::Protocol::Authentication::CLEARTEXT_PASSWORD
          @password
        when Vertica::Protocol::Authentication::CRYPT_PASSWORD
          @password.crypt(@salt)
        when Vertica::Protocol::Authentication::MD5_PASSWORD, Vertica::Protocol::Authentication::HASH, Vertica::Protocol::Authentication::HASH_MD5, Vertica::Protocol::Authentication::HASH_SHA512
          # Encodes user/password/salt information in the following way:
          #   MD5(MD5(password + user) + salt)
          #   SHA512(SHA512(password + userSalt) + salt)
          use_md5 = [Authentication::MD5_PASSWORD, Authentication::HASH_MD5].include?(@auth_method)
          user = use_md5 ? @user : @usersalt

          [user, @salt].each do |key|
            digest_algorithm = use_md5 ? Digest::MD5.new : Digest::SHA512.new
            digest_algorithm.update(@password + key)
            hexdigest = digest_algorithm.hexdigest
            @password = hexdigest.encode(Encoding::UTF_8)
          end
          prefix = use_md5 ? 'md5' : 'sha512'
          prefix + @password
        else
          raise ArgumentError.new("unsupported authentication method: #{@auth_method}")
        end
      end

      def message_body
        [encoded_password].pack('Z*')
      end
    end
  end
end
