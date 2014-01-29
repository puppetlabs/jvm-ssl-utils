require 'rspec'
require 'puppet'
require 'puppet/network/http_pool'

Puppet.initialize_settings ['--confdir', 'test-resources/client/conf',
                            '--certname', 'local-client']

describe 'Plaintext request localhost:8080/test/ssl/' do
  it "should return 'Access granted'" do
    http = Puppet::Network::HttpPool.http_instance('localhost', 8080, false)
    response = http.get('/test-ssl/')
    response.code.should == '200'
    response.body.should == 'Access granted'
  end
end

describe 'HTTPS request to localhost:8081/test-ssl/' do
  it "should return 'Access granted'" do
    http = Puppet::Network::HttpPool.http_instance('localhost', 8081, true)
    response = http.get('/test-ssl/')
    response.code.should == '200'
    response.body.should == 'Access granted'
  end
end
