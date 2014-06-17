(ns puppetlabs.certificate-authority.core
  (:import (java.security Key KeyPair PrivateKey PublicKey KeyStore)
           (java.security.cert X509Certificate X509CRL)
           (javax.net.ssl KeyManagerFactory TrustManagerFactory SSLContext)
           (javax.security.auth.x500 X500Principal)
           (org.bouncycastle.asn1.x500 X500Name)
           (org.bouncycastle.pkcs PKCS10CertificationRequest)
           (com.puppetlabs.certificate_authority CertificateAuthority))
  (:require [clojure.tools.logging :as log]
            [clojure.walk :refer [keywordize-keys]]
            [clojure.java.io :refer [reader writer]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Predicates

(defn keypair?
  "Returns true if x is a keypair (see `generate-key-pair`)."
  [x]
  (instance? KeyPair x))

(defn public-key?
  "Returns true if x is a public key (see `generate-key-pair`)."
  [x]
  (instance? PublicKey x))

(defn private-key?
  "Returns true if x is a private key (see `generate-key-pair`)."
  [x]
  (instance? PrivateKey x))

(defn x500-name?
  "Returns true if x is an instance of `X500Name` (see `generate-x500-name`)."
  [x]
  (instance? X500Name x))

(defn x500-principal?
  "Returns true if x is an instance of 'X500Principal'."
  [x]
  (instance? X500Principal x))

(defn certificate-request?
  "Returns true if x is an instance of `PKCS10CertificationRequest` (see `generate-certificate-request`)."
  [x]
  (instance? PKCS10CertificationRequest x))

(defn certificate?
  "Returns true if x is an instance of `X509Certificate` (see `sign-certificate-request`)."
  [x]
  (instance? X509Certificate x))

(defn certificate-revocation-list?
  "Returns true if x is an instance of `X509CRL` (see `generate-crl`)."
  [x]
  (instance? X509CRL x))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Core

(defn keylength
  "Given a key, return the length key length that was used when generating it."
  [key]
  {:pre  [(or (public-key? key)
              (private-key? key))]
   :post [(integer? %)]}
  (-> key .getModulus .bitLength))

(def default-key-length
  "The default key length to use when generating a keypair."
  CertificateAuthority/DEFAULT_KEY_LENGTH)

(defn generate-key-pair
  "Given a key length (defaults to 4096), generate a new public & private key pair."
  ([]
     {:post [(keypair? %)]}
     (CertificateAuthority/generateKeyPair))
  ([key-length]
     {:pre  [(integer? key-length)]
      :post [(keypair? %)]}
     (CertificateAuthority/generateKeyPair key-length)))

(defn generate-x500-name
  "Given a common name, return an X500 name built from it."
  [common-name]
  {:pre  [(string? common-name)]
   :post [(x500-name? %)]}
  (CertificateAuthority/generateX500Name common-name))

(defn x500-name->CN
  "Given an X500 name, return the common name from it."
  [x500-name]
  {:pre  [(x500-name? x500-name)]
   :post [(string? %)]}
  (CertificateAuthority/getCommonNameFromX500Name x500-name))

(defn generate-certificate-request
  "Given the subject's keypair and name, create and return a certificate signing request (CSR).
  Arguments:

  `keypair`:      subject's public & private keys
  `subject-name`: subject's `X500Name`

  See `sign-certificate-request`, `obj->pem!`, and `pem->csr` to sign & read/write CSRs."
  [keypair subject-name]
  {:pre  [(keypair? keypair)
          (x500-name? subject-name)]
   :post [(certificate-request? %)]}
  (CertificateAuthority/generateCertificateRequest keypair subject-name))

(defn sign-certificate-request
  "Given a certificate signing request and certificate authority information, sign the request
  and return the signed `X509Certificate`.  Arguments:

  `request`:            the certificate signing request
  `issuer`:             the issuer's `X500Name`
  `serial`:             an arbitrary serial number integer
  `issuer-private-key`: the issuer's `PrivateKey`

  See `generate-certificate-request`, `obj->pem!`, and `pem->certs` to create & read/write certificates."
  [request issuer serial issuer-private-key]
  {:pre  [(certificate-request? request)
          (x500-name? issuer)
          (number? serial)
          (private-key? issuer-private-key)]
   :post [(certificate? %)]}
  (CertificateAuthority/signCertificateRequest request issuer (biginteger serial) issuer-private-key))

(defn generate-crl
  "Given the certificate authority's principal identifier and private key, create and return
  a `X509CRL` certificate revocation list (CRL).  Arguments:

  `issuer`:             the issuer's `X500Principal`
  `issuer-private-key`: the issuer's `PrivateKey`"
  [issuer issuer-private-key]
  {:pre  [(instance? X500Principal issuer)
          (private-key? issuer-private-key)]
   :post [(certificate-revocation-list? %)]}
  (CertificateAuthority/generateCRL issuer issuer-private-key))

(defn crl->pem!
  "Encodes a CRL to PEM format, and writes it to a file (or other stream).
   Arguments:

   `crl`: the `X509CRL` to encode
   `pem`: the file path to write the PEM output to
          (or some other object supported by clojure's `writer`)"
  [crl pem]
  {:pre  [(certificate-revocation-list? crl)
          (not (nil? pem))]
   :post [(nil? %)]}
  (with-open [w (writer pem)]
    (CertificateAuthority/writeToPEM crl w)))

(defn pem->crl
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
   decode the contents into a `X509CRL`.

   See `crl->pem!` to PEM-encode a certificate revocation list."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(certificate-revocation-list? %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/pemToCRL r)))

(defn pem->csr
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decode the contents into a `PKCS10CertificationRequest`.

  See `obj->pem!` to PEM-encode a certificate signing request."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(certificate-request? %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/pemToCertificateRequest r)))

(defn keystore
  "Create an empty in-memory Java KeyStore object."
  []
  {:post [(instance? KeyStore %)]}
  (CertificateAuthority/createKeyStore))

(defn pem->objs
  "Given a file path (or some other object supported by clojure's `reader`), reads
  PEM-encoded objects and returns a collection of objects of the corresponding
  type from `java.security`."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(coll? %)]}
  (with-open [r (reader pem)]
    (let [objs (seq (CertificateAuthority/pemToObjects r))]
      (doseq [o objs]
        (log/debug (format "Loaded PEM object of type '%s' from '%s'" (class o) pem)))
      objs)))

(defn obj->pem!
  "Encodes an object in PEM format, and writes it to a file (or other stream).  Arguments:

  `obj`: the object to encode and write.  Must be of a type that can be encoded
         to PEM; usually this is limited to certain types from the `java.security`
         packages.

  `pem`: the file path to write the PEM output to (or some other object supported by clojure's `writer`)"
  [obj pem]
  {:pre  [(not (nil? obj))
          (not (nil? pem))]
   :post [(nil? %)]}
  (with-open [w (writer pem)]
    (CertificateAuthority/writeToPEM obj w)))

(defn pem->certs
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into a collection of `X509Certificate` instances."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(every? certificate? %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/pemToCerts r)))

(defn pem->cert
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into an `X509Certificate`."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(certificate? %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/pemToCert r)))

(defn cert->pem!
  "Encodes a certificate to PEM format, and writes it to a file (or other stream).
   Arguments:

   `cert`: the `X509Certificate` to encode and write
   `pem`: the file path to write the PEM output to
          (or some other object supported by clojure's `writer`)"
  [cert pem]
  {:pre  [(certificate? cert)
          (not (nil? pem))]
   :post [(nil? %)]}
  (with-open [w (writer pem)]
    (CertificateAuthority/writeToPEM cert w)))

(defn obj->private-key
  "Decodes the given object (read from a .pem via `pem->objs`) into an instance of `PrivateKey`."
  [obj]
  {:pre  [(not (nil? obj))]
   :post [(private-key? %)]}
  (CertificateAuthority/objectToPrivateKey obj))

(defn pem->private-keys
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into a collection of `PrivateKey` instances."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(every? private-key? %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/pemToPrivateKeys r)))

(defn pem->private-key
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decode the contents into a `PrivateKey` instance. Throws an exception if multiple keys
  are found in the PEM.
  See `key->pem!` and `pem->private-keys` to write/read keys."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(private-key? %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/pemToPrivateKey r)))

(defn pem->public-key
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
   decode the contents into a `PublicKey` instance. Throws an exception if multiple
   keys are found in the PEM.
   See `key->pem!` to write public keys."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(public-key? %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/pemToPublicKey r)))

(defn key->pem!
  "Encodes a public or private key to PEM format, and writes it to a file (or other
  stream).  Arguments:

  `key`: the key to encode and write; usually an instance of `PrivateKey` or `PublicKey`
  `pem`: the file path to write the PEM output to (or some other object supported by clojure's `writer`)"
  [key pem]
  {:pre  [(instance? Key key)
          (not (nil? pem))]
   :post [(nil? %)]}
  (with-open [w (writer pem)]
    (CertificateAuthority/writeToPEM key w)))

(defn assoc-cert!
  "Add a certificate to a keystore.  Arguments:

  `keystore`: the `KeyStore` to add the certificate to
  `alias`:    a String alias to associate with the certificate
  `cert`:     an `X509Certificate` to add to the keystore"
  [keystore alias cert]
  {:pre  [(instance? KeyStore keystore)
          (string? alias)
          (certificate? cert)]
   :post [(instance? KeyStore %)]}
  (CertificateAuthority/associateCert keystore alias cert))

(defn assoc-certs-from-reader!
  "Add all certificates from a PEM file to a keystore.  Arguments:

  `keystore`: the `KeyStore` to add certificates to
  `prefix`:   an alias to associate with the certificates. each
              certificate will have a numeric index appended to
              its alias, starting with '-0'
  `pem`:      the path to a PEM file containing the certificate
              (or some other object supported by clojure's `reader`)"
  [keystore prefix pem]
  {:pre  [(instance? KeyStore keystore)
          (string? prefix)
          (not (nil? pem))]
   :post [(instance? KeyStore %)]}
  (with-open [r (reader pem)]
    (CertificateAuthority/associateCertsFromReader keystore prefix r)))

(def assoc-certs-from-file!
  "Alias for `assoc-certs-from-reader!` for backwards compatibility."
  assoc-certs-from-reader!)

(defn assoc-private-key!
  "Add a private key to a keystore.  Arguments:

  `keystore`:    the `KeyStore` to add the private key to
  `alias`:       a String alias to associate with the private key
  `private-key`: the `PrivateKey` to add to the keystore
  `pw`:          a password to use to protect the key in the keystore
  `cert`:        the `X509Certificate` for the private key; a private key
                 cannot be added to a keystore without a signed certificate."
  [keystore alias private-key pw cert]
  {:pre  [(instance? KeyStore keystore)
          (string? alias)
          (private-key? private-key)
          (string? pw)
          (or (nil? cert)
              (certificate? cert))]
   :post [(instance? KeyStore %)]}
  (CertificateAuthority/associatePrivateKey keystore alias private-key pw cert))

(defn assoc-private-key-from-reader!
  "Add a private key to a keystore.  Arguments:

  `keystore`:        the `KeyStore` to add the private key to
  `alias`:           a String alias to associate with the private key
  `pem-private-key`: the path to a PEM file containing the private key to add to
                     the keystore (or some other object supported by clojure's `reader`)
  `pw`:              a password to use to protect the key in the keystore
  `pem-cert`:        the path to a PEM file (or some other object supported by clojure's `reader`)
                     containing the certificate for the private key; a private key cannot be added
                     to a keystore without a signed certificate."
  [keystore alias pem-private-key pw pem-cert]
  {:pre  [(instance? KeyStore keystore)
          (string? alias)
          (not (nil? pem-private-key))
          (string? pw)]
   :post [(instance? KeyStore %)]}
  (with-open [key-reader  (reader pem-private-key)
              cert-reader (reader pem-cert)]
    (CertificateAuthority/associatePrivateKeyFromReader keystore alias key-reader pw cert-reader)))

(def assoc-private-key-file!
  "Alias for `assoc-private-key-from-reader!` for backwards compatibility."
  assoc-private-key-from-reader!)

(defn pems->key-and-trust-stores
  "Given pems for a certificate, private key, and CA certificate, creates an
  in-memory KeyStore and TrustStore.

  Argument should be a map containing the keys `:cert`, `:key`, and `:ca-cert`.
  Each value must be an object suitable for use with clojure's `reader`, and
  reference a PEM that contains the appropriate cert/key.

  Returns a map containing the following keys:

  `:keystore`    - an instance of KeyStore initialized with the cert and private key
  `:keystore-pw` - a string containing a dynamically generated password for the KeyStore
  `:truststore`  - an instance of KeyStore containing the CA cert."
  [cert private-key ca-cert]
  {:pre  [(not (nil? cert))
          (not (nil? private-key))
          (not (nil? ca-cert))]
   :post [(map? %)
          (= #{:keystore :truststore :keystore-pw} (-> % keys set))
          (instance? KeyStore (:keystore %))
          (instance? KeyStore (:truststore %))
          (string? (:keystore-pw %))]}
  (with-open [cert-reader    (reader cert)
              key-reader     (reader private-key)
              ca-cert-reader (reader ca-cert)]
    (->> (CertificateAuthority/pemsToKeyAndTrustStores cert-reader key-reader ca-cert-reader)
         (into {})
         (keywordize-keys))))

(defn get-key-manager-factory
  "Given a map containing a KeyStore and keystore password (e.g. as generated by
  pems->key-and-trust-stores), return a KeyManagerFactory that contains the
  KeyStore."
  [{:keys [keystore keystore-pw]}]
  {:pre  [(instance? KeyStore keystore)
          (string? keystore-pw)]
   :post [(instance? KeyManagerFactory %)]}
  (CertificateAuthority/getKeyManagerFactory keystore keystore-pw))

(defn get-trust-manager-factory
  "Given a map containing a trust store (e.g. as generated by
  pems->key-and-trust-stores), return a TrustManagerFactory that contains the
  trust store."
  [{:keys [truststore]}]
  {:pre  [(instance? KeyStore truststore)]
   :post [(instance? TrustManagerFactory %)]}
  (CertificateAuthority/getTrustManagerFactory truststore))

(defn pems->ssl-context
  "Given pems for a certificate, private key, and CA certificate, creates an
  in-memory SSLContext initialized with a KeyStore/TrustStore generated from
  the input certs/key.

  Each argument must be an object suitable for use with clojure's `reader`, and
  reference a PEM that contains the appropriate cert/key.

  Returns the SSLContext instance."
  [cert private-key ca-cert]
  {:pre  [(not (nil? cert))
          (not (nil? private-key))
          (not (nil? ca-cert))]
   :post [(instance? SSLContext %)]}
  (with-open [cert-reader    (reader cert)
              key-reader     (reader private-key)
              ca-cert-reader (reader ca-cert)]
    (CertificateAuthority/pemsToSSLContext cert-reader key-reader ca-cert-reader)))

(defn ca-cert-pem->ssl-context
  "Given a pem for a CA certificate, creates an in-memory SSLContext initialized
  with a TrustStore generated from the input CA cert.

  `ca-cert` must be an object suitable for use with clojure's `reader`, and
  reference a PEM that contains the CA cert.

  Returns the SSLContext instance."
  [ca-cert]
  {:pre  [ca-cert]
   :post [(instance? SSLContext %)]}
  (with-open [ca-cert-reader (reader ca-cert)]
    (CertificateAuthority/caCertPemToSSLContext ca-cert-reader)))

(defn get-extension-value
  "Given a certificate, retrieve the parsed string value of an extension by its
  OID."
  [cert oid]
  {:pre [(certificate? cert)
         (string? oid)]
   :post [(string? %)]}
  (CertificateAuthority/getDecodedExtensionValue cert oid))

(defn get-critical-extensions
  "Given a certificate, retrieve all critical extensions."
  [cert]
  {:pre [(certificate? cert)]}
  (CertificateAuthority/getCriticalExtensions cert))

(defn get-noncritical-extensions
  "Given a certificate, retrieve all the non-critical extensions."
  [cert]
  {:pre [(certificate? cert)]}
  (CertificateAuthority/getNonCriticalExtensions cert))

(defn get-cn-from-x500-principal
  "Given an X500Principal object, retrieve the common name (CN)."
  [x500-principal]
  {:pre [(x500-principal? x500-principal)]
   :post [(string? %)]}
  (CertificateAuthority/getCnFromX500Principal x500-principal))