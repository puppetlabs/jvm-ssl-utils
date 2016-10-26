(ns puppetlabs.ssl-utils.core
  (:import (java.security Key KeyPair PrivateKey PublicKey KeyStore)
           (java.security.cert X509Certificate X509CRL X509Extension)
           (javax.net.ssl KeyManagerFactory TrustManagerFactory SSLContext)
           (javax.security.auth.x500 X500Principal)
           (org.bouncycastle.asn1.x500 X500Name)
           (org.bouncycastle.pkcs PKCS10CertificationRequest)
           (com.puppetlabs.ssl_utils SSLUtils
                                     ExtensionsUtils)
           (java.util Map List Date Set)
           (org.bouncycastle.asn1.x500.style BCStyle))
  (:require [clojure.tools.logging :as log]
            [clojure.walk :as walk]
            [clojure.string :as string]
            [clojure.java.io :refer [reader writer]]
            [puppetlabs.i18n.core :as i18n]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Predicates

(defn valid-x500-name?
  "Returns true if x is a valid X500 name string."
  ;; TODO: Maybe using a string parsing algo is faster?
  [x]
  (try
    (X500Name. BCStyle/INSTANCE x)
    (not (nil? x))
    (catch Exception _
      false)))

(defn extension?
  "Returns true if the given map contains all the fields required to define an
  extension."
  [x]
  (and (map? x)
       (string? (:oid x))
       (not (nil? (:critical x)))
       (not (nil? (:value x)))))

(defn extension-list?
  "Returns true if the given data structure is a list that contains extensions."
  [x]
  (and (sequential? x)
       (every? extension? x)))

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

(defn x500-principal?
  "Returns true if x is an instance of 'X500Principal'."
  [x]
  (instance? X500Principal x))

(defn x509-extension?
  "Returns true if the given object contains X509 extensions, this generally
  refers to `X509Certificate` and `X509CRL` objects."
  [x]
  (instance? X509Extension x))

;; TODO: (PE-4778) This library should not leak Bouncy Castle objects
(defn certificate-request?
  "Returns true if x is an instance of `PKCS10CertificationRequest` (see `generate-certificate-request`)."
  [x]
  (instance? PKCS10CertificationRequest x))

(defn certificate?
  "Returns true if x is an instance of `X509Certificate` (see `sign-certificate-request`)."
  [x]
  (instance? X509Certificate x))

(defn certificate-list?
  "Returns true if the given data structure is a list that contains
  certificates."
  [x]
  (and (instance? List x)
       (every? certificate? x)))

(defn certificate-revocation-list?
  "Returns true if x is an instance of `X509CRL` (see `generate-crl`)."
  [x]
  (instance? X509CRL x))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Internal

(defn clojureize
  "Convert a Java data structure returned from a Java utility method into a
  Clojure data structure."
  [data-structure]
  (cond
    (instance? Map data-structure)
    (-> (into {} (map (fn [[k v]] [(string/replace k #"_" "-") (clojureize v)])
                      data-structure))
        walk/keywordize-keys)

    (instance? List data-structure)
    (mapv clojureize data-structure)

    (instance? Set data-structure)
    (set (map #(keyword (string/replace % #"_" "-")) data-structure))

    (and ((complement nil?) data-structure)
         (.isArray (.getClass data-structure)))
    (vec data-structure)

    :else
    data-structure))

(defn javaize
  "Convert a Clojure data structure passed into a function by a user into a Java
  data structure suitable for passing into a Java utility method."
  [data-structure]
  (cond
    (map? data-structure)
    (into {} (map (fn [[k v]]
                    [(string/replace k #"-" "_") (javaize v)])
                  (walk/stringify-keys data-structure)))

    (sequential? data-structure)
    (mapv javaize data-structure)

    (set? data-structure)
    (set (map javaize data-structure))

    (keyword? data-structure)
    (string/replace (name data-structure) #"-" "_")

    :else
    data-structure))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; OID definitions

(def crl-number-oid
  "CRLNumber OID 2.5.29.20"
  ExtensionsUtils/CRL_NUMBER_OID)

(def authority-key-identifier-oid
  "AuthorityKeyIdentifier OID 2.5.29.35"
  ExtensionsUtils/AUTHORITY_KEY_IDENTIFIER_OID)

(def subject-alt-name-oid
  "SubjectAlternativeName OID 2.5.29.17"
  ExtensionsUtils/SUBJECT_ALTERNATIVE_NAME_OID)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Extensions

(defn get-extensions
  "Given an object containing X509 extensions, retrieve a list of maps of all
  extensions. Each map in the list contains the following keys:

  `oid`      : The OID of the extension
  `value`    : The value of the extensions
  `critical` : True if this is a critical extensions, false if it is not."
  [ext-container]
  {:pre [(or (certificate? ext-container)
             (certificate-request? ext-container)
             (certificate-revocation-list? ext-container))]
   :post [(extension-list? %)]}
  (-> (or (ExtensionsUtils/getExtensionList (javaize ext-container))
          [])
      clojureize))

(defn get-extension
  "Given a X509 certificate object, CRL, CSR, or a list of extensions
  returned by `get-extensions`, return a map describing the value and
  criticality of the extension described by its OID."
  [ext-container oid]
  {:pre [(or (certificate? ext-container)
             (certificate-request? ext-container)
             (certificate-revocation-list? ext-container)
             (instance? List ext-container))
         (string? oid)]
   :post [(extension? %)]}
  (-> (ExtensionsUtils/getExtension (javaize ext-container) oid)
      clojureize))

(defn get-extension-value
  "Given a X509 certificate object, CRL, CSR or a list of extensions returned by
  `get-extensions`, return the value of an extension by its OID. If the OID
  doesn't exist on the provided object, then nil is returned."
  [ext-container oid]
  {:pre [(or (certificate? ext-container)
             (certificate-request? ext-container)
             (certificate-revocation-list? ext-container)
             (instance? List ext-container))
         (string? oid)]}
  (-> (ExtensionsUtils/getExtensionValue (javaize ext-container) oid)
      clojureize))

(defn subject-dns-alt-names
  "Create a Subject Alternative Names extensions (OID=2.5.29.17) which contains
  a list of DNS names as alternative names. The `critical` argument sets the
  criticality flag of this extension."
  [alt-names-list critical]
  {:pre [(sequential? alt-names-list)
         (every? string? alt-names-list)]
   :post [(extension? %)]}
  {:oid      subject-alt-name-oid
   :critical (boolean critical)
   :value    {:dns-name alt-names-list}})

(defn get-subject-dns-alt-names
  "Given a certificate or CSR, return the list of DNS alternative names on the
   Subject Alternative Names extension, or nil if the extension is not present."
  [cert-or-csr]
  {:pre  [(or (certificate? cert-or-csr)
              (certificate-request? cert-or-csr))]
   :post [(or (nil? %)
              (and (sequential? %)
                   (every? string? %)))]}
  (:dns-name (get-extension-value cert-or-csr subject-alt-name-oid)))

(defn netscape-comment
  "Create a `Netscape Certificate Comment` extension."
  [comment]
  {:pre  [(string? comment)]
   :post [(extension? %)]}
  {:oid      "2.16.840.1.113730.1.13"
   :critical false
   :value    comment})

(defn- create-authority-key-identifier
  [public-key issuer-dn serial critical]
  {:oid      authority-key-identifier-oid
   :critical (boolean critical)
   :value    {:public-key    public-key
              :serial-number (if (number? serial) (biginteger serial))
              :issuer-dn     issuer-dn}})

(defn authority-key-identifier
  "Create an `Authority Key Identifier` extension from a `PublicKey` object. The
  extension created by this function is intended to be passed into
  `sign-certificate` and `generate-certificate-request`, at which time the key's
  hash will be computed and stored in the resulting object."
  ([public-key critical]
    {:pre [(public-key? public-key)]
     :post [(extension? %)]}
    (create-authority-key-identifier public-key nil nil critical))
  ([issuer-dn serial critical]
    {:pre [(number? serial)
           (valid-x500-name? issuer-dn)]
     :post [(extension? %)]}
    (create-authority-key-identifier nil issuer-dn serial critical))
  ([public-key issuer-dn serial critical]
    {:pre [(public-key? public-key)
           (valid-x500-name? issuer-dn)
           (number? serial)]
     :post [(extension? %)]}
    (create-authority-key-identifier public-key issuer-dn serial critical)))

(defn subject-key-identifier
  "Create a `Subject Key Identifier` extension from a `PublicKey` object. The
  extension created by this function is intended to be passed into
  `sign-certificate` and `generate-certificate-request`, at which time the key's
  hash will be computed and stored in the resulting object."
  [public-key critical]
  {:pre [(public-key? public-key)]
   :post [(extension? %)]}
  {:oid      "2.5.29.14"
   :critical (boolean critical)
   :value    public-key})

(defn key-usage
  "Create a `Key Usage` extension from a set of flags to enable. See the
  README.md for the keys supported."
  [flag-set critical]
  {:pre  [(set? flag-set)]
   :post [(extension? %)]}
  {:oid     "2.5.29.15"
   :critical (boolean critical)
   :value   flag-set})

(defn ext-key-usages
  "Create an `Extended Key Usages` extensions from a list of OIDs."
  [oid-list critical]
  {:pre [(sequential? oid-list)]
   :post [(extension? %)]}
  {:oid "2.5.29.37"
   :critical (boolean critical)
   :value oid-list})

(defn basic-constraints-for-non-ca
  "Create a `Basic Constraints` extension for a non-CA certificate."
  [critical]
  {:post [(extension? %)]}
  {:oid "2.5.29.19"
   :critical (boolean critical)
   :value {:is-ca false}})

(defn basic-constraints-for-ca
  "Create a `Basic Constraints` extension for a CA certificate.  `max-path-len`
  refers to the maximum number of non-self-issued intermediate certificates that
  may follow the CA certificate in a valid certification path.  If `max-path-len`
  is not specified, no limit will be imposed."
  ([]
   {:post [(extension? %)]}
   {:oid "2.5.29.19"
    :critical true
    :value {:is-ca true}})
  ([max-path-len]
   {:pre [(instance? Integer max-path-len)]
    :post [(extension? %)]}
   {:oid "2.5.29.19"
    :critical true
    :value {:is-ca true
            :path-len-constraint max-path-len}}))

(defn crl-number
  "Create a `CRL Number` extension"
  [number]
  {:pre [(number? number)]
   :post [(extension? %)]}
  {:oid crl-number-oid
   :critical false
   :value (biginteger number)})

(defn puppet-node-uid
  "Create a `Puppet Node UID` extension."
  [uid critical]
  {:pre  [(string? uid)]
   :post [(extension? %)]}
  {:oid "1.3.6.1.4.1.34380.1.1.1"
   :critical (boolean critical)
   :value uid})

(defn puppet-node-instance-id
  "Create a `Puppet Node Instance ID` extension."
  [id critical]
  {:pre  [(string? id)]
   :post [(extension? %)]}
  {:oid "1.3.6.1.4.1.34380.1.1.2"
   :critical (boolean critical)
   :value id})

(defn puppet-node-image-name
  "Create a `Puppet Node Image Name` extension."
  [name critical]
  {:pre  [(string? name)]
   :post [(extension? %)]}
  {:oid "1.3.6.1.4.1.34380.1.1.3"
   :critical (boolean critical)
   :value name})

(defn puppet-node-preshared-key
  "Create a `Puppet Node Preshared Key` extension."
  [key critical]
  {:pre  [(string? key)]
   :post [(extension? %)]}
  {:oid "1.3.6.1.4.1.34380.1.1.4"
   :critical (boolean critical)
   :value key})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Core

(defn dn
  "Given a sequence of attribute names and value pairs, generate an X.500 DN
  string. For example, [:cn \"common\" :o \"org\"] would return
  \"CN=common,O=org\""
  [rdns]
  {:pre  [(sequential? rdns)
          (even? (count rdns))
          (> (count rdns) 0)]
   :post [(valid-x500-name? %)]}
  (SSLUtils/x500Name (javaize rdns)))

(defn cn
  "Given a common name, generate an X.500 RDN from it"
  [common-name]
  {:pre [(string? common-name)]
   :post [(valid-x500-name? %)]}
  (SSLUtils/x500NameCn common-name))

(defn keylength
  "Given a key, return the length key length that was used when generating it."
  [key]
  {:pre  [(or (public-key? key)
              (private-key? key))]
   :post [(integer? %)]}
  (-> key .getModulus .bitLength))

(def default-key-length
  "The default key length to use when generating a keypair."
  SSLUtils/DEFAULT_KEY_LENGTH)

(defn generate-key-pair
  "Given a key length (defaults to 4096), generate a new public & private key pair."
  ([]
     {:post [(keypair? %)]}
     (SSLUtils/generateKeyPair))
  ([key-length]
     {:pre  [(integer? key-length)]
      :post [(keypair? %)]}
     (SSLUtils/generateKeyPair key-length)))

(defn x500-name->CN
  "Given an X500 name, return the common name from it."
  [x500-name]
  {:pre  [(valid-x500-name? x500-name)]
   :post [(string? %)]}
  (SSLUtils/getCommonNameFromX500Name x500-name))

(defn generate-certificate-request
  "Given the subject's keypair and name, create and return a certificate signing request (CSR).
  Arguments:

  `keypair`:      subject's public & private keys
  `subject-name`: subject's X500 distinguished name
  `extensions`: an optional collection of `Extension` objects to add to the certificate request

  See `sign-certificate-request`, `obj->pem!`, and `pem->csr` to sign & read/write CSRs."
  ([keypair subject-dn]
   (generate-certificate-request keypair subject-dn []))
  ([keypair subject-dn extensions]
   {:pre  [(keypair? keypair)
           (valid-x500-name? subject-dn)
           (extension-list? extensions)]
    :post [(certificate-request? %)]}
   (SSLUtils/generateCertificateRequest
     keypair subject-dn (javaize extensions))))

(defn sign-certificate
  "Given a subject, certificate authority information and other certificate info,
  return a signed  `X509Certificate` object.

  Arguments:

  `issuer-dn`:          a string containing the issuer's DN.
  `issuer-priv-key`:    the issuer's private key.
  `serial`:             an arbitrary serial number integer.
  `not-before`:         the certificate's 'not before' date.
  `not-after`:          the certificate's 'not after' date.
  `subject-dn`:         the subject's DN
  `subject-pub-key`:    the subject's public key
  `extensions`:         an optional list of X509 extensions, each of which is
                        a map with an `oid`, `value` and `critical` flag. The
                        value format is dependent upon the oid."
  ([issuer-dn issuer-priv-key serial not-before not-after
    subject-dn subject-pub-key]
    (sign-certificate issuer-dn issuer-priv-key serial not-before not-after
                      subject-dn subject-pub-key []))
  ([issuer-dn issuer-priv-key serial not-before not-after
    subject-dn subject-pub-key extensions]
   {:pre [(valid-x500-name? issuer-dn)
          (private-key? issuer-priv-key)
          (number? serial)
          (instance? Date not-before)
          (instance? Date not-after)
          (valid-x500-name? subject-dn)
          (public-key? subject-pub-key)
          (extension-list? extensions)]
    :post [(certificate? %)]}
   (SSLUtils/signCertificate
     issuer-dn issuer-priv-key (biginteger serial) not-before not-after subject-dn
     subject-pub-key (javaize extensions))))

(defn generate-crl
  "Given the certificate authority's principal identifier and private & public
   keys, create and return a `X509CRL` certificate revocation list (CRL).
   The CRL will have an AuthorityKeyIdentifier and CRLNumber extensions.

   Arguments:
   `issuer`:             the issuer's `X500Principal`
   `issuer-private-key`: the issuer's `PrivateKey`
   `issuer-public-key`:  the issuer's `PublicKey`"
  [issuer issuer-private-key issuer-public-key]
  {:pre  [(instance? X500Principal issuer)
          (private-key? issuer-private-key)
          (public-key? issuer-public-key)]
   :post [(certificate-revocation-list? %)]}
  (SSLUtils/generateCRL issuer issuer-private-key issuer-public-key))

(defn revoked?
  "Given a certificate revocation list and certificate, test if the
   certificate has been revoked.

   Note that if the certificate and CRL have different issuers, false
   will be returned even if the certificate's serial number is on the
   CRL (i.e. previously revoked)."
  [crl certificate]
  {:pre [(certificate-revocation-list? crl)
         (certificate? certificate)]}
  (SSLUtils/isRevoked crl certificate))

(defn revoke
  "Given a certificate revocation list and certificate serial number,
   revoke the certificate by adding its serial number to the list and
   return the updated CRL. The issuer keys should be the same ones
   that were used when generating the CRL.

   The CRLNumber extension on the CRL will be incremented by 1,
   or the extension will be added if it doesn't already exist.

   The AuthorityKeyIdentifier extension will be added to the CRL
   if it doesn't already exist."
  [crl issuer-private-key issuer-public-key cert-serial]
  {:pre  [(certificate-revocation-list? crl)
          (private-key? issuer-private-key)
          (public-key? issuer-public-key)
          (number? cert-serial)]
   :post [(certificate-revocation-list? %)]}
  (SSLUtils/revoke crl issuer-private-key
                               issuer-public-key cert-serial))

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
    (SSLUtils/writeToPEM crl w)))

(defn pem->crl
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
   decode the contents into a `X509CRL`.

   See `crl->pem!` to PEM-encode a certificate revocation list."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(certificate-revocation-list? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToCRL r)))

(defn pem->crls
  "Given the path to a PEM file (or some other object supported by clojure's
  `reader`), decode the contents into a collection of `X509CRL` instances."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(every? certificate-revocation-list? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToCRLs r)))

(defn pem->csr
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decode the contents into a `PKCS10CertificationRequest`.

  See `obj->pem!` to PEM-encode a certificate signing request."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(certificate-request? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToCertificateRequest r)))

(defn keystore
  "Create an empty in-memory Java KeyStore object."
  []
  {:post [(instance? KeyStore %)]}
  (SSLUtils/createKeyStore))

(defn pem->objs
  "Given a file path (or some other object supported by clojure's `reader`), reads
  PEM-encoded objects and returns a collection of objects of the corresponding
  type from `java.security`."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(coll? %)]}
  (with-open [r (reader pem)]
    (let [objs (seq (SSLUtils/pemToObjects r))]
      (doseq [o objs]
        (log/debug (i18n/trs "Loaded PEM object of type ''{0}'' from ''{1}''"
                             (class o) pem)))
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
    (SSLUtils/writeToPEM obj w)))

(defn pem->certs
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into a collection of `X509Certificate` instances."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(every? certificate? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToCerts r)))

(defn pem->cert
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into an `X509Certificate`."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(certificate? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToCert r)))

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
    (SSLUtils/writeToPEM cert w)))

(defn obj->private-key
  "Decodes the given object (read from a .pem via `pem->objs`) into an instance of `PrivateKey`."
  [obj]
  {:pre  [(not (nil? obj))]
   :post [(private-key? %)]}
  (SSLUtils/objectToPrivateKey obj))

(defn pem->private-keys
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into a collection of `PrivateKey` instances."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(every? private-key? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToPrivateKeys r)))

(defn pem->private-key
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decode the contents into a `PrivateKey` instance. Throws an exception if multiple keys
  are found in the PEM.
  See `key->pem!` and `pem->private-keys` to write/read keys."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(private-key? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToPrivateKey r)))

(defn pem->public-key
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
   decode the contents into a `PublicKey` instance. Throws an exception if multiple
   keys are found in the PEM.
   See `key->pem!` to write public keys."
  [pem]
  {:pre  [(not (nil? pem))]
   :post [(public-key? %)]}
  (with-open [r (reader pem)]
    (SSLUtils/pemToPublicKey r)))

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
    (SSLUtils/writeToPEM key w)))

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
  (SSLUtils/associateCert keystore alias cert))

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
    (SSLUtils/associateCertsFromReader keystore prefix r)))

(def assoc-certs-from-file!
  "Alias for `assoc-certs-from-reader!` for backwards compatibility."
  assoc-certs-from-reader!)

(defn assoc-private-key!
  "Add a private key to a keystore.  Arguments:

  `keystore`:    the `KeyStore` to add the private key to
  `alias`:       a String alias to associate with the private key
  `private-key`: the `PrivateKey` to add to the keystore
  `pw`:          a password to use to protect the key in the keystore
  `certs`:       the `X509Certificate` or a list of `X509Certificate`s for the
                 private key; a private key cannot be added to a keystore
                 without at least one signed certificate."
  [keystore alias private-key pw certs]
  {:pre  [(instance? KeyStore keystore)
          (string? alias)
          (private-key? private-key)
          (string? pw)
          (or (nil? certs)
              (certificate? certs)
              (certificate-list? certs))]
   :post [(instance? KeyStore %)]}
  (SSLUtils/associatePrivateKey keystore alias private-key pw
                                            certs))

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
    (SSLUtils/associatePrivateKeyFromReader keystore alias key-reader pw cert-reader)))

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
    (->> (SSLUtils/pemsToKeyAndTrustStores cert-reader key-reader ca-cert-reader)
         (into {})
         (walk/keywordize-keys))))

(defn get-key-manager-factory
  "Given a map containing a KeyStore and keystore password (e.g. as generated by
  pems->key-and-trust-stores), return a KeyManagerFactory that contains the
  KeyStore."
  [{:keys [keystore keystore-pw]}]
  {:pre  [(instance? KeyStore keystore)
          (string? keystore-pw)]
   :post [(instance? KeyManagerFactory %)]}
  (SSLUtils/getKeyManagerFactory keystore keystore-pw))

(defn get-trust-manager-factory
  "Given a map containing a trust store (e.g. as generated by
  pems->key-and-trust-stores), return a TrustManagerFactory that contains the
  trust store."
  [{:keys [truststore]}]
  {:pre  [(instance? KeyStore truststore)]
   :post [(instance? TrustManagerFactory %)]}
  (SSLUtils/getTrustManagerFactory truststore))

(defn pems->ssl-context
  "Given pems for a certificate, private key, and CA certificate, creates an
  in-memory SSLContext initialized with a KeyStore/TrustStore generated from
  the input certs/key.  If an optional argument containing CRLs is provided,
  the SSLContext is also enabled for revocation checking against the CRLs.

  Each argument must be an object suitable for use with clojure's `reader`, and
  reference a PEM that contains the appropriate cert/key/crl list.

  Returns the SSLContext instance."
  ([cert private-key ca-cert]
    {:pre [(not (nil? cert))
           (not (nil? private-key))
           (not (nil? ca-cert))]
     :post [(instance? SSLContext %)]}
    (pems->ssl-context cert private-key ca-cert nil))
  ([cert private-key ca-cert crls]
    {:pre  [(not (nil? cert))
            (not (nil? private-key))
            (not (nil? ca-cert))]
     :post [(instance? SSLContext %)]}
    (with-open [cert-reader    (reader cert)
                key-reader     (reader private-key)
                ca-cert-reader (reader ca-cert)]
      (if crls
        (with-open [crls-reader (reader crls)]
          (SSLUtils/pemsToSSLContext cert-reader
                                                 key-reader
                                                 ca-cert-reader
                                                 crls-reader))
        (SSLUtils/pemsToSSLContext cert-reader
                                               key-reader
                                               ca-cert-reader)))))

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
    (SSLUtils/caCertPemToSSLContext ca-cert-reader)))

(defn ca-cert-and-crl-pems->ssl-context
  "Given a pem for a CA certificate and one or more CRLs, creates an in-memory
  SSLContext initialized with a TrustStore generated from the input CA cert
  and enabled for revocation checking against the CRLs.

  `ca-cert` must be an object suitable for use with clojure's `reader` and
  reference a PEM that contains the CA cert.

  `crls` must be an object suitable for use with clojure's `reader` and
  reference a PEM that contains one or more CRLs.

  Returns the SSLContext instance."
  [ca-cert crls]
  {:pre  [ca-cert crls]
   :post [(instance? SSLContext %)]}
  (with-open [ca-cert-reader (reader ca-cert)
              crls-reader    (reader crls)]
    (SSLUtils/caCertAndCrlPemsToSSLContext ca-cert-reader
                                                       crls-reader)))

(defn generate-ssl-context
  "Given a map of options, extracts the SSL Options and attempts to create an SSLContext.

   This function grabs five keys from a map, all of which are optional: :ssl-context, :ssl-key,
   :ssl-ca-cert, :ssl-cert, and :ssl-ca-crl. The value stored at :ssl-context, if present, should
   be an instance of an SSLContext object. The other keys should be objects suitable for use with
   clojure's `reader` and reference PEMs that contain the proper cert/key/crl list.

   If the :ssl-context key is present, returns the value stored at that key.

   Otherwise, if the :ssl-cert, :ssl-key, and :ssl-ca-cert keys are all present, returns an
   SSLContext constructed from those pems.

   Otherwise, if the :ssl-ca-cert and :ssl-ca-crl keys are present, returns an SSLContext
   constructed from those pems.

   Otherwise, if the :ssl-ca-cert key is present, returns an SSLContext constructed from the
   ca-cert pem.

   If none of the :ssl-cert, :ssl-key, :ssl-ca-cert, :ssl-ca-crl, or :ssl-context keys are present,
   returns nil.

   If the :ssl-context and :ssl-ca-cert keys are both missing, an exception will be thrown."
  [options]
  {:pre [(map? options)]
   :post [(or (nil? %) (instance? SSLContext %))]}
  (let [ssl-opts (select-keys options [:ssl-cert :ssl-key :ssl-ca-cert :ssl-ca-crls :ssl-context])
        from-context?           (contains? ssl-opts :ssl-context)
        from-pems?              (every? ssl-opts [:ssl-cert :ssl-key :ssl-ca-cert])
        from-cert-and-crl-pems? (every? ssl-opts [:ssl-ca-cert :ssl-ca-crls])
        from-ca-cert-pem?       (contains? ssl-opts :ssl-ca-cert)
        no-ssl-config?          (empty? ssl-opts)]
    (cond
      from-context? (:ssl-context ssl-opts)
      from-pems?    (pems->ssl-context
                      (:ssl-cert ssl-opts)
                      (:ssl-key ssl-opts)
                      (:ssl-ca-cert ssl-opts)
                      (:ssl-ca-crls ssl-opts))
      from-cert-and-crl-pems? (ca-cert-and-crl-pems->ssl-context
                                (:ssl-ca-cert ssl-opts)
                                (:ssl-ca-crls ssl-opts))
      from-ca-cert-pem?       (ca-cert-pem->ssl-context
                                (:ssl-ca-cert ssl-opts))
      no-ssl-config?          nil
      :else                   (throw
                                (IllegalArgumentException.
                                  "Error: Attempted to configure SSL, but only partial SSL configuration
                                   provided.")))))

(defn get-cn-from-x500-principal
  "Given an X500Principal object, retrieve the common name (CN)."
  [x500-principal]
  {:pre [(x500-principal? x500-principal)]
   :post [(string? %)]}
  (SSLUtils/getCnFromX500Principal x500-principal))

(defn get-cn-from-x509-certificate
  "Given an X509Certificate object, retrieve its common name (CN)."
  [x509-certificate]
  {:pre [(certificate? x509-certificate)]
   :post [(string? %)]}
  (-> (.getSubjectX500Principal x509-certificate)
      get-cn-from-x500-principal))

(defn get-subject-from-x509-certificate
  "Given an X509Certificate object, retrieve its subject."
  [x509-certificate]
  {:pre [(certificate? x509-certificate)]
   :post [(string? %)]}
  (SSLUtils/getSubjectFromX509Certificate x509-certificate))

(defn get-public-key
  "Given an object which contains a public key, extract the public key
  and return it."
  [key-object]
  {:pre [(or (certificate-request? key-object)
             (keypair? key-object))]
   :post [(public-key? %)]}
  (SSLUtils/getPublicKey key-object))

(defn get-private-key
  "Given an object which contains a private key, extract and return it."
  [key-object]
  {:pre [(keypair? key-object)]
   :post [(private-key? %)]}
  (SSLUtils/getPrivateKey key-object))

(defn get-serial
  "Given an X509 certificate, return the serial number from it."
  [cert]
  {:pre  [(certificate? cert)]
   :post [(instance? BigInteger %)]}
  (SSLUtils/getSerialNumber cert))

(defn subtree-of?
  "Given an OID and a a parent tree OID return true if the OID is within
  the subtree of the parent OID."
  [parent-oid oid]
  {:pre [(string? parent-oid)
         (string? oid)]}
  (ExtensionsUtils/isSubtreeOf parent-oid oid))

(defn signature-valid?
  "Does the given CSR have a valid signature on it?  i.e., was it signed by the
  private key corresponding to the public key included in the CSR?"
  [csr]
  {:pre [(certificate-request? csr)]}
  (SSLUtils/isSignatureValid csr))

(defn fingerprint
  "Given a certificate or CSR, hash the object using the digest algorithm and
   return it as a hex string. The digest algorithm is expected to be one of
   SHA-1, SHA-256, or SHA-512."
  [c digest]
  {:pre  [(or (certificate? c)
              (certificate-request? c))
          (string? digest)]
   :post [(string? %)]}
  (SSLUtils/getFingerprint c digest))
