require "test/unit"
require "socket"
require "net/http"

class RubyMessenger
  DEFAULT_HOST = "messenger.hotmail.com"
  DEFAULT_PORT = 1863
  BUFFER_SIZE = 1*1024
  MSNP_VERSION = "MSNP18 CRV0"
  
  def initialize(host=DEFAULT_HOST, port=DEFAULT_PORT)
    @host = host
    @port = port
    @tid = 0
  end
  
  def connect(email, password)
    @socket = TCPSocket.open(@host, @port)
    ver MSNP_VERSION
    cvr "0x0409 mac 10 i386 RMSN 1.0 MSMSGS #{email}"

    resp = usr "TWN I #{email}"
    reg = /(?:\d{1,3}\.){3}\d{1,3}:\d{1,4}/.match(resp)[0]
    sb_host = reg.split(":")[0]
    sb_port = reg.split(":")[1]
    
    @socket.close
    
    @socket = TCPSocket.open(sb_host, sb_port)
    ver MSNP_VERSION
    cvr "0x0409 mac 10 i386 RMSN 1.0 MSMSGS #{email}"
    resp = usr "TWN I #{email}"
    cookies = MSNP_VERSION.include?("MSNP8") ? resp[12..-1] : resp[(resp.index("TWN S")+6)..-1]
    ticket = authenticate_with_ssl 4, cookies, email, password
    usr "TWN S #{ticket}"
    
    @socket.close
  end
  
  def method_missing(method, *args, &block)
    super if method.to_s.size != 3
    send_command(method.to_s.upcase, args[0])
  end
  
  private
  
  def tid
    @tid = @tid + 1
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
  
  def authenticate_with_ssl(id, cookies, email, password)
    server = "loginnet.passport.com"

    headers = {
      "Authorization" => "Passport1.4 OrgVerb=GET,OrgURL=http%3A%2F%2Fmessenger%2Emsn%2Ecom,sign-in=#{email},pwd=#{password},#{cookies}",
      "User-Agent" => "MSMSGS",
      "Host" => "login.passport.com",
      "Connection" => "Keep-Alive",
      "Cache-Control" => "no-cache"
    }
    Net::HTTP.version_1_1
    http = Net::HTTP.new(server, 443)
    http.use_ssl = true
    response = nil
    http.start do |http|
      response = http.request_get("/login2.srf", headers)
      response.value
    end
    data = response["Authentication-Info"]
    
    puts data

    if data.index("from-PP='") 
       return data.split("'")[1]
    else
      puts "wrong password!"
    end
  end
end