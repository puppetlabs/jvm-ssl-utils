# jvm-ssl-utils

[![Build Status](https://travis-ci.org/puppetlabs/jvm-ssl-utils.png?branch=master)](https://travis-ci.org/puppetlabs/jvm-ssl-utils)

SSL certificate management on the JVM.

## Installation

Add the following dependency to your `project.clj` file:

[![Clojars Project](http://clojars.org/puppetlabs/ssl-utils/latest-version.svg)](http://clojars.org/puppetlabs/ssl-utils)

## Handling X.509 certificate extensions

X.509 certificates and certificate requests can optionally contain a list of
extensions which may further specify how the certificate is to be used. Each of
the functions which either return or accept X.509 extensions expect them to
be a list of maps. Each map contains the following keys:

* `oid` A string containing the extension's OID.
* `critical` A boolean which is true if the extension is marked as critical.
* `value` A primitive value, or data structure representing the data contained
          in the extension. The exact format of the `value` data is dependent
          upon the OID of the extension, which are described below.

### Supported extensions and their data structures

Currently only a subset of the defined X.509 extensions are supported by this
library, more will be supported in the future. Note that in the Java API all
map keys are snake-cased strings, in the Clojure API all map keys are kebab-cased
keywords.

#### Subject Key Identifier: `2.5.29.14`

When writing a _Subject Key Identifier_ extension, set the `value` key of the
extension map to an instance of the subject's `java.security.PublicKey`. When
extension is written to the certificate or certificate request then the SHA-1
hash of the key will be computed and written to the object.

When a _Subject Key Identifier_ extensions is read from a certificate its value
is a byte array containing the SHA-1 hash.

#### Key Usage: `2.5.29.15`

Key usage is defined by a set of keywords which indicate how the certificate is
to be used. The following keywords are used:

| Keyword              | Meaning                                                                                   |
|----------------------|-------------------------------------------------------------------------------------------|
| `:digital-signature` | The public key can be used for encrypting data.                                           |
| `:non-repudiation`   | The public key is used to verify digital signatures.                                      |
| `:key-encipherment`  | The certificate will be used with a protocol that encrypts keys.                          |
| `:data-encipherment` | The public key is used for encrypting user data.                                          |
| `:key-agreement`     | The sender and receiver of the public key need to derive the key without using encryption.|
| `:key-cert-sign`     | The subject public key is used to verify a signature on certificates.                     |
| `:crl-sign`          | The subject public key is to verify a signature on a CRL.                                 |
| `:encipher-only`     | The public key is to be used only for enciphering data while performing key agreement.    |
| `:decipher-only`     | The public key is to be used only for deciphering data while performing key agreement.    |

#### Subject Alternative Names: `2.5.29.17`

This extensions is represented as a map where each key is name type, and the
value is a list of names of that type to be aliased. The following hash keys
correspond to the listed types.

| Key               | Type                                     |
|-------------------|------------------------------------------|
| `:rfc822-name`    | An RFC822 compliant e-mail address       |
| `:dns-name`       | A host name which can be resolved by DNS |
| `:directory-name` | A fully-qualified DN                     |
| `:uri`            | A URI                                    |
| `:ip`             | An IP address                            |

For example:

```clojure
(let [exts [;; Subject alternative DNS names
            {:oid      "2.5.29.17"
             :value    {:dns-name ["aliasname1.domain.tld"
                                   "aliasname2.domain.tld"]}
             :critical false}
            ;; Issuer alternative DNS name
            {:oid      "2.5.29.18"
             :value    {:dns-name ["aliasname3.domain.tld"}
             :critical false}]])
```

#### Issuer Alternative Names: `2.5.29.18`

The format of this extension is the same as `Subject Alternative Names` above.

#### Basic Constraints: `2.5.29.19`

Defines basic constraints for the certificate as a map with these two keys:

| Key                    | Type    | Value                                                                                                                                |
|------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------|
| `:is-ca`               | boolean | True if the subject may act as a CA.                                                                                                 |
| `:path-len-constraint` | integer | If this is a CA cert, the max certification path length.  A value of nil or absence of this key indicates that no length is imposed. |

#### CRL Number: `2.5.29.20`

The value of this extension is a `java.math.BigInteger` representing the
sequence number for a CRL (Certificate Revocation List).

#### Authority Key Identifier: `2.5.29.35`

When writing this extension to a certificate the value should be a map
which contains one of the following combinations of keys (with corresponding
values):

* `:public-key`
* `:serial-number` and `:issuer-dn`
* `:public-key`, `:serial-number`, and `:issuer-dn`

These keys are defined as:

| Key              | Type                    | Value                                    |
|------------------|-------------------------|------------------------------------------|
| `:public-key`    | java.security.PublicKey | CA's public key.                         |
| `:issuer-dn`     | string                  | A Distinguished Name identifying the CA. |
| `:serial-number` | java.math.BigInteger    | CA's serial number.                      |

When this extension is read back from a certificate, it will be a map containing
the following keys.  Note that if the corresponding value for any key was not
specified, it will be set to nil.

| Key                    | Type                 | Value                                                          |
|------------------------|----------------------|----------------------------------------------------------------|
| `:key-identifier`      | byte vector          | A byte array containing the SHA-1 hash of the CA's public key. |
| `:issuer`              | string               | A Distinguished Name identifying the CA.                       |
| `:serial-number`       | java.math.BigInteger | CA's serial number.                                            |

#### Extended Key Usage: `2.5.29.37`

#### Netscape Certificate Comment: `2.16.840.1.113730.1.13`

The value of this extension is a string containing a comment about the certificate.

## License

See [LICENSE](LICENSE) file.

## Support

Please log tickets and issues at our [JIRA tracker](http://tickets.puppetlabs.com).

We use semantic version numbers for our releases, and recommend that users stay
as up-to-date as possible by upgrading to patch releases and minor releases as
they become available.

Bugfixes and ongoing development will occur in minor releases for the current
major version. Security fixes will be backported to a previous major version on
a best-effort basis, until the previous major version is no longer maintained.

## Maintenance

Maintainers: Jeremy Barlow <jeremy.barlow@puppet.com>, Justin Stoller <justin@puppet.com>

Tickets: https://tickets.puppetlabs.com/browse/SERVER
