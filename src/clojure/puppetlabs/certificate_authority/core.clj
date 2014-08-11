(ns puppetlabs.certificate-authority.core
  (:import (java.security Key KeyPair PrivateKey PublicKey KeyStore)
           (java.security.cert X509Certificate X509CRL X509Extension)
           (javax.net.ssl KeyManagerFactory TrustManagerFactory SSLContext)
           (javax.security.auth.x500 X500Principal)
           (org.bouncycastle.asn1.x500 X500Name)
           (org.bouncycastle.pkcs PKCS10CertificationRequest)
           (com.puppetlabs.certificate_authority CertificateAuthority
                                                 ExtensionsUtils
                                                 ExtensionsUtils$PuppetExtensionOids)
           (java.util Map List Date Set)
           (org.bouncycastle.asn1.x509 Extension))
  (:require [clojure.tools.logging :as log]
            [clojure.walk :as walk]
            [clojure.string :as string]
            [clojure.java.io :refer [reader writer]]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Predicates

(defn valid-x500-name?
  "Returns true if x is a valid X500 name string."
  ;; TODO: Maybe using a string parsing algo is faster?
  [x]
  (try
    (X500Name. x)
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
;;; Core

(defn subject-dns-alt-names
  "Create a Subject Alternative Names extensions (OID=2.5.29.17) which contains
  a list of DNS names as alternative names. The `critical` argument sets the
  criticality flag of this extension."
  [alt-names-list critical]
  {:pre [(sequential? alt-names-list)
         (every? string? alt-names-list)]
   :post [(extension? %)]}
  {:oid      "2.5.29.17"
   :critical (boolean critical)
   :value    {:dns-name alt-names-list}})

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
  {:oid      "2.5.29.35"
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
  {:oid "2.5.29.20"
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

(defn dn
  "Given a sequence of attribute names and value pairs, generate an X.500 DN
  string. For example, [:cn \"common\" :o \"org\"] would return
  \"CN=common,O=org\""
  [rdns]
  {:pre  [(sequential? rdns)
          (even? (count rdns))
          (> (count rdns) 0)]
   :post [(valid-x500-name? %)]}
  (CertificateAuthority/x500Name (javaize rdns)))

(defn cn
  "Given a common name, generate an X.500 RDN from it"
  [common-name]
  {:pre [(string? common-name)]
   :post [(valid-x500-name? %)]}
  (CertificateAuthority/x500NameCn common-name))

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

(defn x500-name->CN
  "Given an X500 name, return the common name from it."
  [x500-name]
  {:pre  [(valid-x500-name? x500-name)]
   :post [(string? %)]}
  (CertificateAuthority/getCommonNameFromX500Name x500-name))

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
   (CertificateAuthority/generateCertificateRequest
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
   (CertificateAuthority/signCertificate
     issuer-dn issuer-priv-key (biginteger serial) not-before not-after subject-dn
     subject-pub-key (javaize extensions))))

(defn generate-crl
  "Given the certificate authority's principal identifier, private key, and,
  optionally, some extensions info, create and return a `X509CRL` certificate
  revocation list (CRL).  Arguments:

  `issuer`:             the issuer's `X500Principal`
  `issuer-private-key`: the issuer's `PrivateKey`
  `extensions`:         an optional list of X509 extensions, each of which is
                        a map with an `oid`, `value` and `critical` flag. The
                        value format is dependent upon the oid."
  ([issuer issuer-private-key]
   (generate-crl issuer issuer-private-key []))
  ([issuer issuer-private-key extensions]
    {:pre  [(instance? X500Principal issuer)
            (private-key? issuer-private-key)
            (extension-list? extensions)]
     :post [(certificate-revocation-list? %)]}
    (CertificateAuthority/generateCRL issuer issuer-private-key
                                      (javaize extensions))))

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
         (walk/keywordize-keys))))

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

(defn get-cn-from-x500-principal
  "Given an X500Principal object, retrieve the common name (CN)."
  [x500-principal]
  {:pre [(x500-principal? x500-principal)]
   :post [(string? %)]}
  (CertificateAuthority/getCnFromX500Principal x500-principal))

(defn get-public-key
  "Given an object which contains a public key, extract the public key
  and return it."
  [key-object]
  {:pre [(or (certificate-request? key-object)
             (keypair? key-object))]
   :post [(public-key? %)]}
  (CertificateAuthority/getPublicKey key-object))

(defn get-private-key
  "Given an object which contains a private key, extract and return it."
  [key-object]
  {:pre [(keypair? key-object)]
   :post [(private-key? %)]}
  (CertificateAuthority/getPrivateKey key-object))

(defn subtree-of?
  "Given an OID and a a parent tree OID return true if the OID is within
  the subtree of the parent OID."
  [parent-oid oid]
  {:pre [(string? parent-oid)
         (string? oid)]}
  (ExtensionsUtils/isSubtreeOf parent-oid oid))
