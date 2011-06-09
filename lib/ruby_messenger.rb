require "test/unit"
require "socket"
require "net/http"
require "nokogiri"
require "hmac-sha1"
require "base64"
require "uuidtools"

class RubyMessenger
  DEFAULT_HOST = "messenger.hotmail.com"
  DEFAULT_PORT = 1863
  BUFFER_SIZE = 8 * 1024
  MSNP_VERSION = "MSNP21 CVR0"
  DEFAULT_CVR = "0x0409 winnt 6.1.0 i386 MSNMSGR 15.4.3508.1109 MSNMSGR"
  SSO_HOST = "https://login.live.com/RST.srf"
  SSO_MSN_HOST = "https://msnia.login.live.com/pp550/RST.srf"
  
  def initialize(host=DEFAULT_HOST, port=DEFAULT_PORT)
    @host = host
    @port = port
    @tid = 0
  end
  
  def connect(email, password)
    # Gets the SwitchBoard server info
    @socket = TCPSocket.open(@host, @port)
    ver MSNP_VERSION
    cvr "#{DEFAULT_CVR} #{email}"
    
    resp = usr "SSO I #{email}"
    reg = /(?:\d{1,3}\.){3}\d{1,3}:\d{1,4}/.match(resp)[0]
    sb_host = reg.split(":")[0]
    sb_port = reg.split(":")[1]
    
    @socket.close
    
    # Gets SSO policy and nounce
    @socket = TCPSocket.open(sb_host, sb_port)
    ver MSNP_VERSION
    cvr "#{DEFAULT_CVR} #{email}"
    resp = usr "SSO I #{email}"
    pdata = /[a-zA-Z_0-9+-]* (?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.match(resp)[0]
    policy = pdata.split[0]
    nonce = pdata.split[1]
    
    # Permorfs the SSO authentication
    sso = auth_sso(email, password, policy)
    struct = encrypt_key(sso[:secret], nonce)    
    usr "SSO S #{sso[:ticket]} #{struct} #{machine_id}"
    
    loop do
      (l = @socket.readpartial 1014)
      puts l
      break if l.include?"UBX "
    end
    
    chg "NLN"
    
    while (l = @socket.readpartial 1014).size > 0
      puts l
    end
    
    
    @socket.close
  end
  
  def auth_sso(email, password, policy)
    template = File.open("lib/auth_soap_template.xml").read()
    template.gsub!(/EMAIL/, email)
    template.gsub!(/PASSWORD/, password)
    template.gsub!(/POLICY/, policy)
    
    uri = URI.parse(email.end_with?("@msn.com") ? SSO_MSN_HOST : SSO_HOST)
    
    http = Net::HTTP.new(uri.host, 443)
    http.use_ssl = true
    response = nil
    http.start do |http|
      response = http.post(uri.request_uri, template)
    end
    
    doc = Nokogiri::XML(response.body)
    ticket = (doc.xpath "//wsse:BinarySecurityToken", "wsse" => "http://schemas.xmlsoap.org/ws/2003/06/secext").text
    secret = (doc.xpath "//wst:BinarySecret", "wst" => "http://schemas.xmlsoap.org/ws/2004/04/trust")[1].text    
    
    return { :ticket => ticket, :secret => secret }
  end
  
  def encrypt_key(secret_key, nonce, iv=nil)
    iv ||= ("\x00" * 8)
    key1 = Base64.decode64 secret_key
    key2 = derive_key key1, "WS-SecureConversationSESSION KEY HASH"
    key3 = derive_key key1, "WS-SecureConversationSESSION KEY ENCRYPTION"
    
    hash = HMAC::SHA1.digest key2, nonce
    
    des = OpenSSL::Cipher::Cipher.new("des-ede3-cbc")
    des.encrypt
    des.key = key3
    des.iv = iv
    ciph = des.update(nonce)
    ciph << des.final
    
    blob = [28, 1, 0x6603, 0x8004, iv.size, hash.size, ciph.size]
    blob = blob.pack "LLLLLLL"
    blob = blob + iv + hash + ciph
    
    Base64.strict_encode64 blob
  end
  
  def derive_key(key, magic)
    hash1 = HMAC::SHA1.digest(key, magic)
    hash2 = HMAC::SHA1.digest(key, hash1 + magic)
    hash3 = HMAC::SHA1.digest(key, hash1)
    hash4 = HMAC::SHA1.digest(key, hash3 + magic)
    return hash2 + hash4[0..3]
  end
  
  def tid
    @tid = @tid + 1
  end  

  def method_missing(method, *args, &block)
    super if method.to_s.size != 3
    send_command(method.to_s.upcase, args[0])
  end
  
  def send_command(command,value)
    data = "#{command} #{tid} #{value}"

    puts "> #{data}"

    @socket.puts data
    @socket.flush
    
    response = String.new
    loop do
      buffer = @socket.readpartial(BUFFER_SIZE)
      response << buffer
      if buffer[-1].ord == 10
        break
      end
    end

    puts "< " + response
    response.chop
  end 
  
  def machine_id
    @machine_id ||= UUIDTools::UUID.random_create.to_s
  end
end