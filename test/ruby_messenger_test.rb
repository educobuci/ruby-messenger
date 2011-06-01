require File.expand_path "lib/ruby_messenger.rb"

class RubyMessengerTest < Test::Unit::TestCase
  def test_connect
    
    puts "Enter you email"
    @email = gets.chop
    
    puts "Enter you password"
    system "stty -echo"
    @password = gets.chop
    system "stty echo"
    
    msn = RubyMessenger.new()
    msn.connect(@email, @password)
  end
end