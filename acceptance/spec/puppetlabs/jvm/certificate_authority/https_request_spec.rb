require 'rspec'
require 'puppet'
require 'puppet/network/http_pool'

SETTINGS = {
  :client_confdir => './acceptance/resources/client',
  :client_certname => 'local-client',
  :host => 'localhost',
  :plaintext_port => 8080,
  :ssl_port => 8081
}

def log_ssl_information
  puts "Test client initialized with: confdir = #{SETTINGS[:client_confdir]}"
  puts "Test client initialized with: certname = #{SETTINGS[:client_certname]}"
  puts
end

def log_response(response)
  puts "Received response with headers:"
  response.header.to_hash.each do |k, v|
    puts "\t#{k} = #{v}"
  end
  puts "Received response with body:"
  puts "\t#{response.body}"
  puts
end

log_ssl_information
Puppet.initialize_settings ['--confdir', SETTINGS[:client_confdir],
                            '--certname', SETTINGS[:client_certname]]

describe "Plaintext request to #{SETTINGS[:host]}:#{SETTINGS[:plaintext_port]}/test-ssl/" do
  it "should return 'Access granted'" do
    http = Puppet::Network::HttpPool.http_instance(SETTINGS[:host], SETTINGS[:plaintext_port], false)
    response = http.get('/test-ssl/')
    log_response response
    response.code.should == '200'
    response.body.should == 'Access granted'
  end
end

describe "HTTPS request to #{SETTINGS[:host]}:#{SETTINGS[:ssl_port]}/test-ssl/" do
  it "should return 'Access granted'" do
    http = Puppet::Network::HttpPool.http_instance(SETTINGS[:host], SETTINGS[:ssl_port], true)
    response = http.get('/test-ssl/')
    log_response response
    response.code.should == '200'
    response.body.should == 'Access granted'
  end
end
