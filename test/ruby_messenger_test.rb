require "msn-config"
require "ruby-messenger"

class RubyMessengerTest < Test::Unit::TestCase
  def setup    
    @email = MsnConfig::EMAIL
    @password = MsnConfig::PASSWORD
    @msn = RubyMessenger.new()
  end
  
  def test_connect    
    @msn.connect(@email, @password)
  end
  
  def test_sso    
    auth = @msn.auth_sso(@email, @password, "MBI_KEY")
    assert_not_nil(auth[:ticket])
    assert_not_nil(auth[:secret])
  end
  
  def test_encrypt
    secret_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    expect = "HAAAAAEAAAADZgAABIAAAAgAAAAUAAAASAAAAAAAAAAAAAAA7XgT5ohvaZdoXdrWUUcMF2G8OK2JohyYcK5l5MJSitab33scxJeK/RQXcUr0L+R2ZA9CEAzn0izmUzSMp2LZdxSbHtnuxCmptgtoScHp9E26HjQVkA9YJxgK/HM="

    msn = RubyMessenger.new()
    final = msn.encrypt_key(secret_key, nonce)
    
    assert_equal expect, final
  end
end