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
           (org.bouncycastle.asn1.x500.style BCStyle)
           (org.bouncycastle.openssl.jcajce JcaPEMWriter)
           (java.io InputStream File Reader BufferedReader Writer OutputStream BufferedWriter)
           (java.net URI URL Socket))
  (:require [clojure.tools.logging :as log]
            [clojure.walk :as walk]
            [clojure.string :as string]
            [clojure.java.io :refer [reader writer]]
            [puppetlabs.i18n.core :as i18n]
            [schema.core :as schema]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Predicates - no longer used internally now that there are schemas
;;;              (except valid-x500-name?)

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
;;; Schemas

(def ValidX500Name
  (schema/pred valid-x500-name?))

(def SSLAttribute
  {:oid schema/Str
   :value Object})

(def SSLAttributeList
  [SSLAttribute])

(def SSLExtension
  "A map containing all the fields required to define an extension. This is not
   the actual SSL Extension itself but the required oid, critical boolean, and
   value for the Extension. Use the optional :options to to modify how the
   extension is created in ExtensionsUtils."
  (assoc SSLAttribute
   :critical schema/Bool
   (schema/optional-key :options) Object))


(def SSLExtensionList
  [SSLExtension])

(def CertOrCSR
  (schema/cond-pre X509Certificate PKCS10CertificationRequest))

(def PublicOrPrivateKey
  (schema/cond-pre PublicKey PrivateKey))

(def ExtensionContainer
  "A schema for all the things that can hold an SSL extension."
  (schema/cond-pre
   X509Certificate
   PKCS10CertificationRequest
   X509CRL
   List))

(def Readerable
  "Schema for anything that can be handed off to clojure's reader function."
  (schema/cond-pre Reader BufferedReader InputStream File URI URL Socket bytes chars String))

(def Writerable
  "Schema for anything that can be handed off to clojure's writer function."
  (schema/cond-pre Writer BufferedWriter OutputStream File URI URL Socket bytes chars String))

(def SSLContextOptions
  "Schema for the options map that generate-ssl-context requires."
  {(schema/optional-key :ssl-cert) Readerable
   (schema/optional-key :ssl-key) Readerable
   (schema/optional-key :ssl-ca-cert) Readerable
   (schema/optional-key :ssl-ca-crls) Readerable
   (schema/optional-key :ssl-context) SSLContext
   schema/Any schema/Any})

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

(def subject-key-identifier-oid
  "SubjectKeyIdentifier OID 2.5.29.14"
  ExtensionsUtils/SUBJECT_KEY_IDENTIFIER_OID)

(def subject-alt-name-oid
  "SubjectAlternativeName OID 2.5.29.17"
  ExtensionsUtils/SUBJECT_ALTERNATIVE_NAME_OID)

(def delta-crl-indicator-oid
  "DeltaCRLIndicator OID 2.5.29.27"
  ExtensionsUtils/DELTA_CRL_INDICATOR_OID)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Extensions

(schema/defn ^:always-validate get-extensions :- SSLExtensionList
  "Given an object containing X509 extensions, retrieve a list of maps of all
  extensions. Each map in the list contains the following keys:

  `oid`      : The OID of the extension
  `value`    : The value of the extensions
  `critical` : True if this is a critical extensions, false if it is not."
  [ext-container :- (schema/cond-pre X509Certificate PKCS10CertificationRequest X509CRL)]
  (-> (or (ExtensionsUtils/getExtensionList (javaize ext-container))
          [])
      clojureize))

(schema/defn ^:always-validate get-extension :- SSLExtension
  "Given a X509 certificate object, CRL, CSR, or a list of extensions
  returned by `get-extensions`, return a map describing the value and
  criticality of the extension described by its OID."
  [ext-container :- ExtensionContainer
   oid :- schema/Str]
  (-> (ExtensionsUtils/getExtension (javaize ext-container) oid)
      clojureize))

(schema/defn ^:always-validate get-extension-value :- schema/Any
  "Given a X509 certificate object, CRL, CSR or a list of extensions returned by
  `get-extensions`, return the value of an extension by its OID. If the OID
  doesn't exist on the provided object, then nil is returned."
  [ext-container :- ExtensionContainer
   oid :- schema/Str]
  (-> (ExtensionsUtils/getExtensionValue (javaize ext-container) oid)
      clojureize))

(schema/defn ^:always-validate subject-dns-alt-names :- SSLExtension
  "Create a Subject Alternative Names extensions (OID=2.5.29.17) which contains
  a list of DNS names as alternative names. The `critical` argument sets the
  criticality flag of this extension."
  [alt-names-list :- [schema/Str]
   critical :- Object]
  {:oid      subject-alt-name-oid
   :critical (boolean critical)
   :value    {:dns-name alt-names-list}})

(schema/defn ^:always-validate get-subject-dns-alt-names :- (schema/maybe [schema/Str])
  "Given a certificate or CSR, return the list of DNS alternative names on the
   Subject Alternative Names extension, or nil if the extension is not present."
  [cert-or-csr :- CertOrCSR]
  (:dns-name (get-extension-value cert-or-csr subject-alt-name-oid)))

(schema/defn ^:always-validate subject-alt-names :- SSLExtension
  "Create a Subject Alternative Names extensions (OID=2.5.29.17) which contains
  a list of DNS and/maybe IP names as alternative names. The `critical` argument sets the
  criticality flag of this extension."
  [alt-names-hashmap :- {schema/Keyword [schema/Str]}
   critical :- Object]
  {:oid      subject-alt-name-oid
   :critical (boolean critical)
   :value    alt-names-hashmap})

(schema/defn ^:always-validate get-subject-ip-alt-names :- (schema/maybe [schema/Str])
 "Given a certificate or CSR, return the list of IP alternative names on the
  Subject Alternative Names extension, or nil if the extension is not present."
 [cert-or-csr :- CertOrCSR]
 (:ip (get-extension-value cert-or-csr subject-alt-name-oid)))

(schema/defn ^:always-validate netscape-comment :- SSLExtension
  "Create a `Netscape Certificate Comment` extension."
  [comment :- schema/Str]
  {:oid      "2.16.840.1.113730.1.13"
   :critical false
   :value    comment})

(defn- create-authority-key-identifier
  [{:keys [public-key issuer-dn serial cert critical]}]
  {:oid      authority-key-identifier-oid
   :critical (boolean critical)
   :value    {:public-key    public-key
              :serial-number (when (number? serial) (biginteger serial))
              :issuer-dn     issuer-dn
              :cert          cert}})

(schema/defn ^:always-validate authority-key-identifier-options :- SSLExtension
  "Create an `Authority Key Identifier` extension from a `PublicKey` object or
   copy the existing `SubjectKeyIdentifier` from a certificate. This function is
   intended to be passed into `sign-certificate` and `generate-certificate-request`.

   PublicKey details:
   A type 1 identifier will be computed from the public key.

   Certificate details:
   An `X509Certificate` can be used instead of a `PublicKey`. The
   `SubjectKeyIdentifier`of the certificate is copied and used for the
   `AuthorityKeyIdentifier` for the certificate about to be signed. When a
   certificate is used, no hash computation takes place."
  ([cert]
   (create-authority-key-identifier {:cert cert :critical false}))
  ([public-key critical]
   (create-authority-key-identifier {:public-key public-key :critical critical}))
  ([issuer-dn serial critical]
   (create-authority-key-identifier {:issuer-dn issuer-dn :serial serial :critical critical}))
  ([public-key :- PublicKey
    issuer-dn :- ValidX500Name
    serial :- schema/Int
    critical :- Object]
   (create-authority-key-identifier {:public-key public-key
                                     :issuer-dn issuer-dn
                                     :serial serial
                                     :critical critical})))

(schema/def authority-key-identifier
  authority-key-identifier-options)

(schema/defn ^:always-validate subject-key-identifier :- SSLExtension
  "Create a `Subject Key Identifier` extension from a `PublicKey` object. The
  extension created by this function is intended to be passed into
  `sign-certificate` and `generate-certificate-request`, at which time the key's
  hash will be computed and stored in the resulting object."
  [public-key :- PublicKey
   critical :- Object]
  {:oid      subject-key-identifier-oid
   :critical (boolean critical)
   :value    public-key})

(schema/defn ^:always-validate key-usage :- SSLExtension
  "Create a `Key Usage` extension from a set of flags to enable. See the
  README.md for the keys supported."
  [flag-set :- #{Object}
   critical :- Object]
  {:oid     "2.5.29.15"
   :critical (boolean critical)
   :value   flag-set})

(schema/defn ^:always-validate ext-key-usages :- SSLExtension
  "Create an `Extended Key Usages` extensions from a list of OIDs."
  [oid-list :- [schema/Str]
   critical :- Object]
  {:oid "2.5.29.37"
   :critical (boolean critical)
   :value oid-list})

(schema/defn ^:always-validate basic-constraints-for-non-ca :- SSLExtension
  "Create a `Basic Constraints` extension for a non-CA certificate."
  [critical :- Object]
  {:oid "2.5.29.19"
   :critical (boolean critical)
   :value {:is-ca false}})

(schema/defn ^:always-validate basic-constraints-for-ca :- SSLExtension
  "Create a `Basic Constraints` extension for a CA certificate.  `max-path-len`
  refers to the maximum number of non-self-issued intermediate certificates that
  may follow the CA certificate in a valid certification path.  If `max-path-len`
  is not specified, no limit will be imposed."
  ([]
   {:oid "2.5.29.19"
    :critical true
    :value {:is-ca true}})
  ([max-path-len :- schema/Int]
   {:oid "2.5.29.19"
    :critical true
    :value {:is-ca true
            :path-len-constraint max-path-len}}))

(schema/defn create-ca-extensions :- (schema/pred extension-list?)
  "Create a list of extensions to be added to the CA certificate."
  ([issuer-public-key :- (schema/pred public-key?)
    ca-public-key :- (schema/pred public-key?)]
   [(authority-key-identifier-options
     issuer-public-key false)
    (basic-constraints-for-ca)
    (key-usage
     #{:key-cert-sign
       :crl-sign} true)
    (subject-key-identifier
     ca-public-key false)])
  ([ca-name :- (schema/pred valid-x500-name?)
    ca-serial :- (schema/pred number?)
    ca-public-key :- (schema/pred public-key?)]
   [(authority-key-identifier-options
     ca-name ca-serial false)
    (basic-constraints-for-ca)
    (key-usage
     #{:key-cert-sign
       :crl-sign} true)
    (subject-key-identifier
     ca-public-key false)]))

(schema/defn ^:always-validate crl-number :- SSLExtension
  "Create a `CRL Number` extension"
  [number :- schema/Int]
  {:oid crl-number-oid
   :critical false
   :value (biginteger number)})

(schema/defn ^:always-validate get-crl-number :- (schema/maybe BigInteger)
  "Given a CRL, return the value of the CRL Number extension, or nil if the
  extension is not present."
  [crl :- X509CRL]
  (get-extension-value crl crl-number-oid))

(schema/defn ^:always-validate puppet-node-uid :- SSLExtension
  "Create a `Puppet Node UID` extension."
  [uid :- schema/Str
   critical :- Object]
  {:oid "1.3.6.1.4.1.34380.1.1.1"
   :critical (boolean critical)
   :value uid})

(schema/defn ^:always-validate puppet-node-instance-id :- SSLExtension
  "Create a `Puppet Node Instance ID` extension."
  [id :- schema/Str
   critical :- Object]
  {:oid "1.3.6.1.4.1.34380.1.1.2"
   :critical (boolean critical)
   :value id})

(schema/defn ^:always-validate puppet-node-image-name :- SSLExtension
  "Create a `Puppet Node Image Name` extension."
  [name :- schema/Str
   critical :- Object]
  {:oid "1.3.6.1.4.1.34380.1.1.3"
   :critical (boolean critical)
   :value name})

(schema/defn ^:always-validate puppet-node-preshared-key :- SSLExtension
  "Create a `Puppet Node Preshared Key` extension."
  [key :- schema/Str
   critical :- Object]
  {:oid "1.3.6.1.4.1.34380.1.1.4"
   :critical (boolean critical)
   :value key})

(schema/defn ^:always-validate delta-crl-indicator :- SSLExtension
  "Create a `Delta CRL Indicator` extension."
  [base-crl-number :- BigInteger]
  {:oid delta-crl-indicator-oid
   :critical true
   :value base-crl-number})

(schema/defn ^:always-validate delta-crl? :- schema/Bool
  [crl :- X509CRL]
  (boolean (get-extension-value crl delta-crl-indicator-oid)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Core

(schema/defn ^:always-validate dn :- ValidX500Name
  "Given a sequence of attribute names and value pairs, generate an X.500 DN
  string. For example, [:cn \"common\" :o \"org\"] would return
  \"CN=common,O=org\""
  [rdns :- (schema/pred #(and (sequential? %) (even? (count %)) (not-empty %)))]
  (SSLUtils/x500Name (javaize rdns)))

(schema/defn ^:always-validate cn :- ValidX500Name
  "Given a common name, generate an X.500 RDN from it"
  [common-name :- schema/Str]
  (SSLUtils/x500NameCn common-name))

(schema/defn ^:always-validate keylength :- schema/Int
  "Given a key, return the length key length that was used when generating it."
  [key :- PublicOrPrivateKey]
  (-> key .getModulus .bitLength))

(def default-key-length
  "The default key length to use when generating a keypair."
  SSLUtils/DEFAULT_KEY_LENGTH)

(schema/defn ^:always-validate generate-key-pair :- KeyPair
  "Given a key length (defaults to 4096), generate a new public & private key pair."
  ([]
   (SSLUtils/generateKeyPair))
  ([key-length :- schema/Int]
   (SSLUtils/generateKeyPair key-length)))

(schema/defn ^:always-validate x500-name->CN :- schema/Str
  "Given an X500 name, return the common name from it."
  [x500-name :- ValidX500Name]
  (SSLUtils/getCommonNameFromX500Name x500-name))

(schema/defn ^:always-validate generate-certificate-request :- PKCS10CertificationRequest
  "Given the subject's keypair and name, create and return a certificate signing request (CSR).
  Arguments:

  `keypair`:      subject's public & private keys
  `subject-name`: subject's X500 distinguished name
  `extensions`: an optional collection of `Extension` objects to add to the certificate request

  See `sign-certificate-request`, `obj->pem!`, and `pem->csr` to sign & read/write CSRs."
  ([keypair subject-dn]
   (generate-certificate-request keypair subject-dn [] []))
  ([keypair :- KeyPair
    subject-dn :- ValidX500Name
    extensions :- SSLExtensionList]
   (generate-certificate-request keypair subject-dn extensions []))
  ([keypair :- KeyPair
    subject-dn :- ValidX500Name
    extensions :- SSLExtensionList
    attributes :- SSLAttributeList]
   (SSLUtils/generateCertificateRequest
     keypair
     subject-dn
     (javaize extensions)
     (javaize attributes))))

(schema/defn ^:always-validate sign-certificate :- X509Certificate
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
  ([issuer-dn :- ValidX500Name
    issuer-priv-key :- PrivateKey
    serial :- schema/Int
    not-before :- Date
    not-after :- Date
    subject-dn :- ValidX500Name
    subject-pub-key :- PublicKey
    extensions :- SSLExtensionList]
   (SSLUtils/signCertificate
     issuer-dn issuer-priv-key (biginteger serial) not-before not-after subject-dn
     subject-pub-key (javaize extensions))))

(schema/defn ^:always-validate generate-crl :- X509CRL
  "Given the certificate authority's principal identifier and private & public
   keys, create and return a `X509CRL` certificate revocation list (CRL).
   The CRL will have an AuthorityKeyIdentifier and CRLNumber extensions. Typical
   usage of this will be with the 3 argument arity; the fuller arity is exposed
   here for testing purposes.

   Arguments:
   `issuer`:             the issuer's `X500Principal`
   `issuer-private-key`: the issuer's `PrivateKey`
   `issuer-public-key`:  the issuer's `PublicKey`
   `this-update`:        date for when this crl is created
   `next-update`:        when to fetch the rcl next
   `crl-number`:         number to start revocation count at
   `extensions`:         any extensions to sign onto the crl"
  ([issuer :- X500Principal
    issuer-private-key :- PrivateKey
    issuer-public-key :- PublicKey]
   (SSLUtils/generateCRL issuer issuer-private-key issuer-public-key))
  ([issuer :- X500Principal
    issuer-private-key :- PrivateKey
    issuer-public-key :- PublicKey
    this-update :- Date
    next-update :- Date
    crl-number :- BigInteger
    extensions :- SSLExtensionList]
   (SSLUtils/generateCRL issuer issuer-private-key issuer-public-key this-update next-update
                         crl-number (javaize extensions))))

(schema/defn ^:always-validate revoked? :- schema/Bool
  "Given a certificate revocation list and certificate, test if the
   certificate has been revoked.

   Note that if the certificate and CRL have different issuers, false
   will be returned even if the certificate's serial number is on the
   CRL (i.e. previously revoked)."
  [crl :- X509CRL
   certificate :- X509Certificate]
  (SSLUtils/isRevoked crl certificate))

(schema/defn ^:always-validate revoke :- X509CRL
  "Given a certificate revocation list and certificate serial number,
   revoke the certificate by adding its serial number to the list and
   return the updated CRL. The issuer keys should be the same ones
   that were used when generating the CRL.

   The CRLNumber extension on the CRL will be incremented by 1,
   or the extension will be added if it doesn't already exist.

   The AuthorityKeyIdentifier extension will be added to the CRL
   if it doesn't already exist."
  [crl :- X509CRL
   issuer-private-key :- PrivateKey
   issuer-public-key :- PublicKey
   cert-serial :- schema/Int]
  (SSLUtils/revoke crl issuer-private-key
                               issuer-public-key cert-serial))

(schema/defn ^:always-validate revoke-multiple :- X509CRL
  "Given a certificate revocation list and a list of certificate
   serial numbers, revoke the certificates by adding their serial
   numbers to the list and returning the updated CRL. The issuer
   keys should be the same ones that were used when generating
   the CRL.

   The CRLNumber extension on the CRL will be incremented by 1,
   or the extension will be added if it doesn't already exist.

   The AuthorityKeyIdentifier extension will be added to the CRL
   if it doesn't already exist."
  [crl :- X509CRL
   issuer-private-key :- PrivateKey
   issuer-public-key :- PublicKey
   cert-serials :- [schema/Int]]
  (SSLUtils/revokeMultiple crl issuer-private-key
                   issuer-public-key cert-serials))

(schema/defn ^:always-validate validate-cert-chain
  "Given a list of certificates and a list of CRLs, validate the certificate
   chain, i.e. ensure that none of the certs have been revoked by checking the
   appropriate CRL, which must be present and currently valid.
   Returns nil if successful."
  [cert-chain :- [X509Certificate]
   crl-chain :- [X509CRL]]
  (SSLUtils/validateCertChain cert-chain crl-chain))

(schema/defn ^:always-validate crl->pem!
  "Encodes a CRL to PEM format, and writes it to a file (or other stream).
   Arguments:

   `crl`: the `X509CRL` to encode
   `pem`: the file path to write the PEM output to
          (or some other object supported by clojure's `writer`)"
  [crl :- X509CRL
   pem :- Writerable]
  (with-open [w (writer pem)]
    (SSLUtils/writeToPEM crl w)))

(schema/defn ^:always-validate pem->crl :- X509CRL
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
   decode the contents into a `X509CRL`.

   See `crl->pem!` to PEM-encode a certificate revocation list."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToCRL r)))

(schema/defn ^:always-validate pem->crls :- [X509CRL]
  "Given the path to a PEM file (or some other object supported by clojure's
  `reader`), decode the contents into a collection of `X509CRL` instances."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToCRLs r)))

(schema/defn ^:always-validate crl-issued-by-cert? :- schema/Bool
  "Given a CRL and a certificate, determine whether the CRL was issued by the
  certificate."
  [crl :- X509CRL
   cert :- X509Certificate]
  (= (.getIssuerX500Principal crl)
     (.getSubjectX500Principal cert)))

(schema/defn ^:always-validate pem->ca-crl :- X509CRL
  "Given a CRL chain and CA certificate, extract the CRL issued by the
  certificate"
  [crl-chain :- Readerable
   ca-cert :- X509Certificate]
  (let [match-ca-cert? (fn [crl] (crl-issued-by-cert? crl ca-cert))
        crls (pem->crls crl-chain)
        crl (first (filter match-ca-cert? crls))]
    (if (nil? crl)
      (throw (IllegalArgumentException.
               "The CRL reader does not contain a CRL matching the given certificate"))
      crl)))

(schema/defn ^:always-validate pem->csr :- PKCS10CertificationRequest
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decode the contents into a `PKCS10CertificationRequest`.

  See `obj->pem!` to PEM-encode a certificate signing request."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToCertificateRequest r)))

(schema/defn ^:always-validate keystore :- KeyStore
  "Create an empty in-memory Java KeyStore object."
  []
  (SSLUtils/createKeyStore))

(schema/defn ^:always-validate pem->objs :- [Object]
  "Given a file path (or some other object supported by clojure's `reader`), reads
  PEM-encoded objects and returns a collection of objects of the corresponding
  type from `java.security`."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (let [objs (seq (SSLUtils/pemToObjects r))]
      (doseq [o objs]
        (log/debug (i18n/trs "Loaded PEM object of type ''{0}'' from ''{1}''"
                             (class o) pem)))
      objs)))

(schema/defn ^:always-validate obj->pem!
  "Encodes an object in PEM format, and writes it to a file (or other stream).  Arguments:

  `obj`: the object to encode and write.  Must be of a type that can be encoded
         to PEM; usually this is limited to certain types from the `java.security`
         packages.

  `pem`: the file path to write the PEM output to (or some other object supported by clojure's `writer`)"
  [obj :- Object
   pem :- Writerable]
  (with-open [w (writer pem)]
    (SSLUtils/writeToPEM obj w)))

(schema/defn ^:always-validate objs->pem!
  "Adds one or more cert related objects, PEM encoded, to the supplied writer"
  [objs :- [Object] ; yes the PEM writer actually takes java.lang.Object
   buf :- Writerable]
  (with-open [w (writer buf)]
    (let [pem-writer (JcaPEMWriter. w)]
      (doseq [obj objs]
        (.writeObject pem-writer obj))
      (.flush pem-writer))))

(schema/defn ^:always-validate pem->certs :- [X509Certificate]
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into a collection of `X509Certificate` instances."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToCerts r)))

(schema/defn ^:always-validate pem->ca-cert :- X509Certificate
  "Given a CA certificate chain and key pair, extract and verify the certificate
  matching the key pair."
  [cert-chain-pem :- Readerable
   key-or-keypair-pem :- Readerable]
  (with-open [cert-chain-pem-reader (reader cert-chain-pem)
              key-pem-reader (reader key-or-keypair-pem)]
    (SSLUtils/pemToCaCert cert-chain-pem-reader key-pem-reader)))

(schema/defn ^:always-validate pem->cert :- X509Certificate
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into an `X509Certificate`."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToCert r)))

(schema/defn ^:always-validate cert->pem!
  "Encodes a certificate to PEM format, and writes it to a file (or other stream).
   Arguments:

   `cert`: the `X509Certificate` to encode and write
   `pem`: the file path to write the PEM output to
          (or some other object supported by clojure's `writer`)"
  [cert :- X509Certificate
   pem :- Writerable]
  (with-open [w (writer pem)]
    (SSLUtils/writeToPEM cert w)))

(schema/defn ^:always-validate obj->private-key :- PrivateKey
  "Decodes the given object (read from a .pem via `pem->objs`) into an instance of `PrivateKey`."
  [obj :- Object]
  (SSLUtils/objectToPrivateKey obj))

(schema/defn ^:always-validate pem->private-keys :- [PrivateKey]
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decodes the contents into a collection of `PrivateKey` instances."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToPrivateKeys r)))

(schema/defn ^:always-validate pem->private-key :- PrivateKey
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
  decode the contents into a `PrivateKey` instance. Throws an exception if multiple keys
  are found in the PEM.
  See `key->pem!` and `pem->private-keys` to write/read keys."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToPrivateKey r)))

(schema/defn ^:always-validate pem->public-key :- PublicKey
  "Given the path to a PEM file (or some other object supported by clojure's `reader`),
   decode the contents into a `PublicKey` instance. Throws an exception if multiple
   keys are found in the PEM.
   See `key->pem!` to write public keys."
  [pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/pemToPublicKey r)))

(schema/defn ^:always-validate key->pem!
  "Encodes a public or private key to PEM format, and writes it to a file (or other
  stream).  Arguments:

  `key`: the key to encode and write; usually an instance of `PrivateKey` or `PublicKey`
  `pem`: the file path to write the PEM output to (or some other object supported by clojure's `writer`)"
  [key :- Key
   pem :- Writerable]
  (with-open [w (writer pem)]
    (SSLUtils/writeToPEM key w)))

(schema/defn ^:always-validate assoc-cert! :- KeyStore
  "Add a certificate to a keystore.  Arguments:

  `keystore`: the `KeyStore` to add the certificate to
  `alias`:    a String alias to associate with the certificate
  `cert`:     an `X509Certificate` to add to the keystore"
  [keystore :- KeyStore
   alias :- schema/Str
   cert :- X509Certificate]
  (SSLUtils/associateCert keystore alias cert))

(schema/defn ^:always-validate assoc-certs-from-reader! :- KeyStore
  "Add all certificates from a PEM file to a keystore.  Arguments:

  `keystore`: the `KeyStore` to add certificates to
  `prefix`:   an alias to associate with the certificates. each
              certificate will have a numeric index appended to
              its alias, starting with '-0'
  `pem`:      the path to a PEM file containing the certificate
              (or some other object supported by clojure's `reader`)"
  [keystore :- KeyStore
   prefix :- schema/Str
   pem :- Readerable]
  (with-open [r (reader pem)]
    (SSLUtils/associateCertsFromReader keystore prefix r)))

(def assoc-certs-from-file!
  "Alias for `assoc-certs-from-reader!` for backwards compatibility."
  assoc-certs-from-reader!)

(schema/defn ^:always-validate assoc-private-key! :- KeyStore
  "Add a private key to a keystore.  Arguments:

  `keystore`:    the `KeyStore` to add the private key to
  `alias`:       a String alias to associate with the private key
  `private-key`: the `PrivateKey` to add to the keystore
  `pw`:          a password to use to protect the key in the keystore
  `certs`:       the `X509Certificate` or a list of `X509Certificate`s for the
                 private key; a private key cannot be added to a keystore
                 without at least one signed certificate."
  [keystore :- KeyStore
   alias :- schema/Str
   private-key :- PrivateKey
   pw :- schema/Str
   certs :- (schema/maybe (schema/cond-pre [X509Certificate] X509Certificate))]
  (SSLUtils/associatePrivateKey keystore alias private-key pw
                                            certs))

(schema/defn ^:always-validate assoc-private-key-from-reader! :- KeyStore
  "Add a private key to a keystore.  Arguments:

  `keystore`:        the `KeyStore` to add the private key to
  `alias`:           a String alias to associate with the private key
  `pem-private-key`: the path to a PEM file containing the private key to add to
                     the keystore (or some other object supported by clojure's `reader`)
  `pw`:              a password to use to protect the key in the keystore
  `pem-cert`:        the path to a PEM file (or some other object supported by clojure's `reader`)
                     containing the certificate for the private key; a private key cannot be added
                     to a keystore without a signed certificate."
  [keystore :- KeyStore
   alias :- schema/Str
   pem-private-key :- Readerable
   pw :- schema/Str
   pem-cert :- Readerable]
  (with-open [key-reader  (reader pem-private-key)
              cert-reader (reader pem-cert)]
    (SSLUtils/associatePrivateKeyFromReader keystore alias key-reader pw cert-reader)))

(def assoc-private-key-file!
  "Alias for `assoc-private-key-from-reader!` for backwards compatibility."
  assoc-private-key-from-reader!)

(def KeyAndTrustStore
  {:keystore KeyStore
   :truststore KeyStore
   :keystore-pw schema/Str})

(schema/defn ^:always-validate pems->key-and-trust-stores :- KeyAndTrustStore
  "Given pems for a certificate, private key, and CA certificate, creates an
  in-memory KeyStore and TrustStore.

  Argument should be a map containing the keys `:cert`, `:key`, and `:ca-cert`.
  Each value must be an object suitable for use with clojure's `reader`, and
  reference a PEM that contains the appropriate cert/key.

  Returns a map containing the following keys:

  `:keystore`    - an instance of KeyStore initialized with the cert and private key
  `:keystore-pw` - a string containing a dynamically generated password for the KeyStore
  `:truststore`  - an instance of KeyStore containing the CA cert."
  [cert :- Readerable
   private-key :- Readerable
   ca-cert :- Readerable]
  (with-open [cert-reader    (reader cert)
              key-reader     (reader private-key)
              ca-cert-reader (reader ca-cert)]
    (->> (SSLUtils/pemsToKeyAndTrustStores cert-reader key-reader ca-cert-reader)
         (into {})
         (walk/keywordize-keys))))

(schema/defn ^:always-validate get-key-manager-factory :- KeyManagerFactory
  "Given a map containing a KeyStore and keystore password (e.g. as generated by
  pems->key-and-trust-stores), return a KeyManagerFactory that contains the
  KeyStore."
  [{:keys [keystore keystore-pw]} :- {:keystore KeyStore :keystore-pw schema/Str}]
  (SSLUtils/getKeyManagerFactory keystore keystore-pw))

(schema/defn ^:always-validate get-trust-manager-factory :- TrustManagerFactory
  "Given a map containing a trust store (e.g. as generated by
  pems->key-and-trust-stores), return a TrustManagerFactory that contains the
  trust store."
  [{:keys [truststore]} :- {:truststore KeyStore}]
  (SSLUtils/getTrustManagerFactory truststore))

(schema/defn ^:always-validate pems->ssl-context :- SSLContext
  "Given pems for a certificate, private key, and CA certificate, creates an
  in-memory SSLContext initialized with a KeyStore/TrustStore generated from
  the input certs/key.  If an optional argument containing CRLs is provided,
  the SSLContext is also enabled for revocation checking against the CRLs.

  Each argument must be an object suitable for use with clojure's `reader`, and
  reference a PEM that contains the appropriate cert/key/crl list.

  Returns the SSLContext instance."
  ([cert private-key ca-cert]
   (pems->ssl-context cert private-key ca-cert nil))
  ([cert :- Readerable
    private-key :- Readerable
    ca-cert :- Readerable
    crls :- (schema/maybe Readerable)]
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

(schema/defn ^:always-validate ca-cert-pem->ssl-context :- SSLContext
  "Given a pem for a CA certificate, creates an in-memory SSLContext initialized
  with a TrustStore generated from the input CA cert.

  `ca-cert` must be an object suitable for use with clojure's `reader`, and
  reference a PEM that contains the CA cert.

  Returns the SSLContext instance."
  [ca-cert :- Readerable]
  (with-open [ca-cert-reader (reader ca-cert)]
    (SSLUtils/caCertPemToSSLContext ca-cert-reader)))

(schema/defn ^:always-validate ca-cert-and-crl-pems->ssl-context :- SSLContext
  "Given a pem for a CA certificate and one or more CRLs, creates an in-memory
  SSLContext initialized with a TrustStore generated from the input CA cert
  and enabled for revocation checking against the CRLs.

  `ca-cert` must be an object suitable for use with clojure's `reader` and
  reference a PEM that contains the CA cert.

  `crls` must be an object suitable for use with clojure's `reader` and
  reference a PEM that contains one or more CRLs.

  Returns the SSLContext instance."
  [ca-cert :- Readerable
   crls :- Readerable]
  (with-open [ca-cert-reader (reader ca-cert)
              crls-reader    (reader crls)]
    (SSLUtils/caCertAndCrlPemsToSSLContext ca-cert-reader
                                                       crls-reader)))

(schema/defn ^:always-validate generate-ssl-context :- (schema/maybe SSLContext)
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
  [options :- SSLContextOptions]
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

(schema/defn ^:always-validate get-cn-from-x500-principal :- schema/Str
  "Given an X500Principal object, retrieve the common name (CN)."
  [x500-principal :- X500Principal]
  (SSLUtils/getCnFromX500Principal x500-principal))

(schema/defn ^:always-validate get-cn-from-x509-certificate :- schema/Str
  "Given an X509Certificate object, retrieve its common name (CN)."
  [x509-certificate :- X509Certificate]
  (-> (.getSubjectX500Principal x509-certificate)
      get-cn-from-x500-principal))

(schema/defn ^:always-validate get-subject-from-x509-certificate :- schema/Str
  "Given an X509Certificate object, retrieve its subject."
  [x509-certificate :- X509Certificate]
  (SSLUtils/getSubjectFromX509Certificate x509-certificate))

(schema/defn ^:always-validate get-public-key :- PublicKey
  "Given an object which contains a public key, extract the public key
  and return it."
  [key-object :- (schema/cond-pre KeyPair PKCS10CertificationRequest)]
  (SSLUtils/getPublicKey key-object))

(schema/defn ^:always-validate get-private-key :- PrivateKey
  "Given an object which contains a private key, extract and return it."
  [key-object :- KeyPair]
  (SSLUtils/getPrivateKey key-object))

(schema/defn ^:always-validate get-serial :- BigInteger
  "Given an X509 certificate, return the serial number from it."
  [cert :- X509Certificate]
  (SSLUtils/getSerialNumber cert))

(schema/defn ^:always-validate subtree-of? :- schema/Bool
  "Given an OID and a a parent tree OID return true if the OID is within
  the subtree of the parent OID."
  [parent-oid :- schema/Str
   oid :- schema/Str]
  (ExtensionsUtils/isSubtreeOf parent-oid oid))

(schema/defn ^:always-validate signature-valid? :- schema/Bool
  "Does the given CSR have a valid signature on it?  i.e., was it signed by the
  private key corresponding to the public key included in the CSR?"
  [csr :- PKCS10CertificationRequest]
  (SSLUtils/isSignatureValid csr))

(schema/defn ^:always-validate fingerprint :- schema/Str
  "Given a certificate or CSR, hash the object using the digest algorithm and
   return it as a hex string. The digest algorithm is expected to be one of
   SHA-1, SHA-256, or SHA-512."
  [c :- CertOrCSR
   digest :- schema/Str]
  (SSLUtils/getFingerprint c digest))
