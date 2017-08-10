## 0.9.0 (2017-08-10)

  * Added lein-parent/clj-parent to set common project dependency versions
  * Function pre/post assertions converted to schemas
  * Added new methods for interacting with certificate bundles and key pairs:
    * `pem->ca-cert`
    * `SSLUtils.pemToCaCert`
    * `SSLUtils.pemTokeyPairs`
    * `SSLUtils.pemTokeyPair`
    * `SSLUtils.certMatchesPubKey`

## 0.8.3 (2016-11-16)
 * Bumps bouncycastle dependency to latest version (1.55)

## 0.8.2
 * Adds `get-subject-from-x509-certificate` and `SSLUtils.getSubjectFromX509Certificate`
   helper methods.

## 0.8.1
 * Fixed problems decoding General Names extensions with values of the type
   "other names."
 * IP addresses General Names are now properly decoded.
 * Introduced new convenience functions for accomplishing common tasks in the
   `puppetlabs.ssl-utils.simple` namespace.

## 0.8.0
 * Added `generate-ssl-context`, a function which, when given a map of options,
   extracts any relevant SSL options and, if any are present, uses them to
   configure an SSLContext.
 * Change signing of X.509 extensions to adhere to the RFC 5280 standard
 * Fix bug in isSubtreeOf wherein extra trailing digits could incorrectly
   be treated as valid.

## 0.7.0
 * Renamed project to jvm-ssl-utils
 * Renamed Clojure namespace from puppetlabs.certificate-authority to puppetlabs.ssl-utils
 * Renamed Java package from com.puppetlabs.certificate_authority to com.puppetlabs.ssl_utils
 * Renamed CertificateAuthority class to SSLUtils

## 0.6.1
 * Added `get-cn-from-x509-certificate` to wrap getSubjectX500Principal and get-cn-from-x500-principal

## 0.6.0
 * Added support for revoking certificates
   * New `revoke` function for adding a certificate to a CRL
   * New `revoked?` function for checking whether a certificate is on a CRL
 * Removed the extensions argument from `generate-crl`
   * The AuthorityKeyIdentifier and CRLNumber extensions are now automatically added
 * Added `fingerprint` for calculating the hash of a certificate or CSR
 * Added `get-subject-dns-alt-names` to get the list of DNS alt names from a cert or CSR
 * Added `get-serial` for pulling the serial number off a certificate
 * Defined constants for OIDs:
   * CRLNumber
   * AuthorityKeyIdentifier
   * SubjectAlternativeName

## 0.5.0
 * Added support for loading chained certificates into a key store, involving the following API changes:
   * New overload of the `associatePrivateKey` Java method which accepts a `List<X509Certificate>`.
   * Removal of the restriction on the `associatePrivateKeyFromReader` Java method and
    `assoc-private-key!` Clojure function to a single certificate.

## 0.4.0
 * Added support for `authority-key-identifier` to specify the distinguished name and serial number of
   the issuer.
 * Split `basic-constraints` into `basic-constraints-for-non-ca` vs. `basic-constraints-for-ca` and allow
   a CA to not set a `max-path-len` (as opposed to it being implicitly set to 0 if not specified).
 * New `crl-number` function for use in generating a CRL Number extension.
 * New `signature-valid?` function for use in determining if the CSR has a valid signature on it.
 * Added ability to specify extensions to be added to a CRL in a call to `generate-crl`.

## 0.3.3
 * If an extension is read that has an unrecognized OID then it is parsed as a string.

## 0.3.2
 * Fixed bugs in how extensions are read and written to signing requests

## 0.3.1
 * Added functions to create a number of common X.509 extensions to certificates and signing requests.
    * Netscape certificate comment
    * authority key identifier
    * subject key identifier
    * key usage
    * extended key usage
    * basic constraints 
    
## 0.3.0
 * Strings are now used to represent X.500 names, instead of Bouncy Castle X500Name objects.
 * The `cn` and `dn` functions are added to facilitate creating X.500 names.
 * Removed the `sign-certificate-request`, and added `sign-certificate` to replace it. 
 * Rudimentary X.500 certificate extension support has been added.
    * Can now extract a number of common certificate extensions
    * Can add Subject and Issuer DNS alternative names to certificates upon signing.

## 0.2.2
 * New `get-cn-from-x500-principal` function to extract the CN from a DN stored in an `X500Principal` object
 * New `get-extensions` function retrieve extension OIDs and values on an object which implements `X509Extension`  

## 0.2.1
 * New `pem->public-key` function

## 0.2.0
 * New `pem->crl` and `crl->pem!` functions for working with CRLs
 * New `pem->cert` and `cert->pem!` functions for working with a certificate
 * Remove `issued-by?` and `has-subject?` functions from API

## 0.1.5
 * New predicate functions for checking the types of various objects
 * Deployment artifacts now include a source jar, which contains the java sources
 * Explicitly target JDK 1.6 when compiling java files
