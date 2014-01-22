require 'rspec'
require 'puppet'
require 'puppet/network/http_pool'

describe 'HTTPS request to localhost:8081/test-ssl/' do
  it "should return 'Access granted'" do
    Puppet.initialize_settings ['--confdir', 'test-resources/client/conf',
                                '--certname', 'local-client']

    http = Puppet::Network::HttpPool.http_ssl_instance('localhost', 8081)
    response = http.get('/test-ssl/')
    response.code.should == '200'
    response.body.should == 'Access granted'
  end
end
