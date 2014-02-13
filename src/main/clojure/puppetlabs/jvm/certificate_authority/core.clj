(ns puppetlabs.jvm.certificate-authority.core
  (:import (java.security Key KeyPair PrivateKey PublicKey KeyStore Security)
           (java.security.cert X509Certificate)
           (org.bouncycastle.openssl PEMParser PEMKeyPair PEMWriter)
           (org.bouncycastle.asn1.pkcs PrivateKeyInfo)
           (org.bouncycastle.openssl.jcajce JcaPEMKeyConverter)
           (org.bouncycastle.cert.jcajce JcaX509CertificateConverter)
           (puppetlabs.jvm.certificate_authority CertificateUtils))
  (:require [clojure.tools.logging :as log]
            [clojure.java.io :refer [reader writer]]))

(defn generate-key-pair
  []
  (CertificateUtils/generateKeyPair))

(defn generate-x500-name
  [common-name]
  (CertificateUtils/generateX500Name common-name))

(defn x500-name->CN
  [x500-name]
  (CertificateUtils/getCommonNameFromX500Name x500-name))

(defn generate-certificate-request
  [keypair subject-name]
  (CertificateUtils/generateCertReq keypair subject-name))

(defn sign-certificate-request
  [request issuer serial issuer-private-key]
  (CertificateUtils/signCertificateRequest request issuer (biginteger serial) issuer-private-key))

(defn generate-crl
  [issuer issuer-private-key]
  (CertificateUtils/generateCRL issuer issuer-private-key))

(defn pem->csr
  [pem]
  (with-open [r (reader pem)]
    (CertificateUtils/pemToCertificationRequest r)))

;;;; SSL functions from Kitchensink below

(defn keystore
  "Create an empty in-memory Java KeyStore object."
  []
  (CertificateUtils/createKeyStore))

(defn pem->objs
  "Given a file path (or any other type supported by clojure's `reader`), reads
  PEM-encoded objects and returns a collection of objects of the
  corresponding type from `java.security`."
  [pem]
  {:post [(coll? %)]}
  (with-open [r (reader pem)]
    (let [objs (seq (CertificateUtils/pemToObjects r))]
      (doseq [o objs]
        (log/debug (format "Loaded PEM object of type '%s' from '%s'" (class o) pem)))
      objs)))

(defn obj->pem!
  "Encodes an object in PEM format, and writes it to a file (or other stream).  Arguments:

  `obj`: the object to encode and write.  Must be of a type that can be encoded
         to PEM; usually this is limited to certain types from the `java.security`
         packages.

  `pem`:   the file path to write the PEM output to.  (Alternately, you may pass a `Writer`
         or any other type that is supported by clojure's `writer`.)"
  [obj pem]
  (with-open [w (writer pem)]
    (CertificateUtils/writeToPEM obj w)))

(defn pem->certs
  "Given the path to a PEM file (or some other object supported by
  clojure's `reader`), decodes the contents into an collection of
  `X509Certificate` instances."
  [pem]
  {:post [(every? (fn [x] (instance? X509Certificate x)) %)]}
  (with-open [r (reader pem)]
    (CertificateUtils/pemToCerts r)))

(defn obj->private-key
  "Decodes the given object (read from a .PEM file via `pem->objs`)
  into an instance of `PrivateKey`"
  [obj]
  {:post [(instance? PrivateKey %)]}
  (CertificateUtils/objectToPrivateKey obj))

(defn pem->private-keys
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into a collection of `PrivateKey` instances."
  [pem]
  {:post [(every? (fn [x] (instance? PrivateKey x)) %)]}
  (with-open [r (reader pem)]
    (CertificateUtils/pemToPrivateKeys r)))

(defn pem->private-key
  [pem]
  {:post [(instance? PrivateKey %)]}
  (with-open [r (reader pem)]
    (CertificateUtils/pemToPrivateKey r)))

(defn key->pem!
  "Encodes a public or private key to PEM format, and writes it to a file (or other
  stream).  Arguments:

  `key`: the key to encode and write.  Usually an instance of `PrivateKey` or `PublicKey`.
  `f`:   the file path to write the PEM output to.  (Alternately, you may pass a `Writer`
         or any other type that is supported by clojure's `writer`.)"
  [key pem]
  {:pre  [(instance? Key key)]}
  (with-open [w (writer pem)]
    (CertificateUtils/writeToPEM key w)))

(defn assoc-cert!
  "Add a certificate to a keystore.  Arguments:

  `keystore`: the `KeyStore` to add the certificate to
  `alias`:    a String alias to associate with the certificate
  `cert`:     an `X509Certificate` to add to the keystore"
  [keystore alias cert]
  {:pre  [(instance? KeyStore keystore)
          (string? alias)
          (instance? X509Certificate cert)]
   :post [(instance? KeyStore %)]}
  (CertificateUtils/associateCert keystore alias cert))

(defn assoc-certs-from-reader!
  "Add all certificates from a PEM file to a keystore.  Arguments:

  `keystore`: the `KeyStore` to add certificates to
  `prefix`:   an alias to associate with the certificates. each
              certificate will have a numeric index appended to
              its alias (starting with '-0'
  `pem`:      the path to a PEM file containing the certificate"
  [keystore prefix pem]
  (with-open [r (reader pem)]
    (CertificateUtils/associateCertsFromReader keystore prefix r)))

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
          (instance? PrivateKey private-key)
          (or (nil? cert)
              (instance? X509Certificate cert))]
   :post [(instance? KeyStore %)]}
  (CertificateUtils/associatePrivateKey keystore alias private-key pw cert))

(defn assoc-private-key-reader!
  "Add a private key to a keystore.  Arguments:

  `keystore`:        the `KeyStore` to add the private key to
  `alias`:           a String alias to associate with the private key
  `pem-private-key`: the path to a PEM file containing the private key to add to
                     the keystore
  `pw`:              a password to use to protect the key in the keystore
  `pem-cert`:        the path to a PEM file containing the certificate for the
                     private key; a private key cannot be added to a keystore
                     without a signed certificate."
  [keystore alias pem-private-key pw pem-cert]
  (with-open [r-key  (reader pem-private-key)
              r-cert (reader pem-cert)]
    (CertificateUtils/associatePrivateKeyReader keystore alias r-key pw r-cert)))

(def assoc-private-key-file!
  "Alias for `assoc-private-key-reader!` for backwards compatibility."
  assoc-private-key-reader!)
