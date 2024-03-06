# https://integrators.vertica.com/data-protocols-formats/frontend-backend/#authentication
module Vertica
  module Protocol
    class Authentication < BackendMessage
      message_id 'R'

      OK                  = 0
      KERBEROS_V4         = 1
      KERBEROS_V5         = 2
      CLEARTEXT_PASSWORD  = 3
      CRYPT_PASSWORD      = 4 # obsolete
      MD5_PASSWORD        = 5
      SCM_CREDENTIAL      = 6
      GSS                 = 7
      GSS_CONTINUE        = 8
      CHANGE_PASSWORD     = 9
      PASSWORD_CHANGED    = 10 # client doesn't do password changing, this should never be seen
      PASSWORD_GRACE      = 11
      OAUTH               = 12
      HASH                = 65536
      HASH_MD5            = 65536+5
      HASH_SHA512         = 65536+512

      attr_reader :code
      attr_reader :salt
      attr_reader :usersalt
      attr_reader :auth_data

      def initialize(data)
        @code, other = data.unpack('Na*')
        case @code
          when CRYPT_PASSWORD then @salt = other
          when MD5_PASSWORD, HASH_MD5 then @salt = other[0...4]
          when HASH, HASH_SHA512
            @salt = other[0...4]
            user_salt_len = other[4, 4].unpack('N').first
            raise Vertica::Error::MessageError, "Received wrong user salt size: #{user_salt_len}" if user_salt_len != 16
            @usersalt = other[8..-1].unpack("a*").first
          when GSS_CONTINUE then @auth_data = other
        end
      end
    end
  end
end
