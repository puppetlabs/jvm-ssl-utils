# jvm-certificate-authority

SSL certificate management on the JVM.

## Running Tests

### Unit Tests

Unit tests are currently in Ruby, but require that a CA test server is up.
Technically they're not unit tests per se, but this method is faster for development
compared to running them via beaker.

Run the following:

1. `lein with-profile +acceptance generate` to create fresh SSL certificates for testing
2. `lein with-profile +acceptance server` to bring up the CA test server
3. `rspec acceptance/spec` to run the spec tests (puppet will need to be on your RUBY_LIB)
4. `lein with-profile +acceptance clean` to remove the generated certificates

### Acceptance Tests

Ruby 1.9, Vagrant, and VirtualBox are required to run the acceptance tests locally.

After cloning the repository, you'll need to run the following:

1. `bundle install --path ./bundle` to pull down the required Ruby gems
2. `bundle exec rake test` to run the tests

#### Environment Variables

Acceptance tests can be configured with the following:

* `REPO_OWNER`: GitHub owner to clone project from (onto the VM); defaults to `puppetlabs`
* `REVISION`: Branch/revision specifier; defaults to `master`
* `BEAKER_CONFIG`: Beaker hosts configuration; one of `acceptance/config`; defaults to `vbox-el6-64`
* `FACTER_VERSION`: Version of Facter to download from GitHub; defaults to `1.7.4`
* `PUPPET_VERSION`: Version of Puppet to download from GitHub; defaults to `3.2.2`
