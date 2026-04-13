## [unreleased]

* Add PKCS#8 encrypted private key helpers: `private-key->pkcs8-pem-str` and
  `pkcs8-pem-str->private-key` for encrypting/decrypting private keys using
  PBES2/AES-256-CBC/PBKDF2-HMAC-SHA256 (Ticket 2.3)
* Add ContentSigner callback support: `SSLUtils.createCallbackContentSigner()`
  for signing without holding a PrivateKey directly, plus signer-accepting
  overloads of `signCertificate` and `generateCRL` (Ticket 2.4)
* Add Clojure wrappers: `sign-certificate-with-signer` and
  `generate-crl-with-signer` that accept a `(fn [bytes algorithm] -> bytes)`
  callback for CA State Externalization signing delegation (Ticket 2.4)

# [3.5.3]
* add functions to SSLUtil to alter and retrieve CRL expiration time
* update clj-parent to 5.6.4
* update issue submission instructions in README.

# [3.5.2]
* remove infinite recursion from ASN1 conversion.
* update clj-parent to 5.6.1 which includes bouncy castle 1.74

# [3.5.1]
* add support for creating csrs with Attributes
* remove use of deprecated routines in ExtensionUtils 
* add support for reading attributes from Certificate Signing Requests

# [3.5.0]
