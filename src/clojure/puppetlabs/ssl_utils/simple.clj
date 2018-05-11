(ns puppetlabs.ssl-utils.simple
  (:import (java.util Date)
           (java.security PublicKey PrivateKey)
           (java.security.cert X509Certificate X509CRL))
  (:require [puppetlabs.ssl-utils.core :as ssl-utils]
            [clj-time.core :as time]
            [schema.core :as schema]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Schemas

(def SSLKeyPair
  "A schema for the map used to describe an SSL KeyPair internally."
  {:public-key PublicKey
   :private-key PrivateKey
   :x500-name ssl-utils/ValidX500Name
   :certname schema/Str})

(def SSLCert
  "A schema for the map used to describe an SSL Certificate internally."
  (assoc SSLKeyPair
    :cert X509Certificate))

(def SSLOptions
  "A schema for the SSL Options that can be used with the cert and key
  generation functions."
  {(schema/optional-key :extensions) [Object]
   (schema/optional-key :keylength) schema/Int})

(def SSLValidDateRange
  "A schema for the map representing a valid date range for an SSL certificate."
  {:not-before Date
   :not-after Date})


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Predicates - no longer used internally now that there are schemas

(defn validity-date-range?
  "Returns true if the given map contains all the fields required to define a
  validity date range for a certificate."
  [x]
  (and (map? x)
    (instance? Date (:not-before x))
    (instance? Date (:not-after x))))

(defn ssl-keys?
  "Returns true if the given map contains all the fields required to define an
  SSL keypair and associated certname info."
  [x]
  (and (map? x)
    (ssl-utils/public-key? (:public-key x))
    (ssl-utils/private-key? (:private-key x))
    (ssl-utils/valid-x500-name? (:x500-name x))
    (string? (:certname x))))

(defn ssl-cert?
  "Returns true if the given map contains all the fields required to define a
  certificate, keypair, and associated certname info."
  [x]
  (and (ssl-keys? x)
    (ssl-utils/certificate? (:cert x))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Public

(schema/defn ^:always-validate cert-validity-dates :- SSLValidDateRange
  "Calculate the not-before & not-after dates that define a certificate's
   period of validity. The value of `ca-ttl` is expected to be in seconds,
   and the dates will be based on the current time. Returns a map in the
   form {:not-before Date :not-after Date}."
  [ca-ttl :- schema/Int]
  (let [now        (time/now)
        not-before (time/minus now (time/days 1))
        not-after  (time/plus now (time/seconds ca-ttl))]
    {:not-before (.toDate not-before)
     :not-after  (.toDate not-after)}))

(def default-keylength
  "The default bit length to use when generating keys.
   Note that all API functions accept an `options' map which may
   have a :keylength for specifying this value."
  4096)

(schema/defn ^:always-validate gen-keys :- SSLKeyPair
  "Generate public and private keys and the X500 name for the given `certname'.
   An optional map may be provided to specify:

   * :keylength  Bit length to use for the public/private keys;
                 defaults to 4096."
  ([certname] (gen-keys certname {}))
  ([certname :- schema/Str
    options :- SSLOptions]
   (let [keylength (get options :keylength default-keylength)
         keypair (ssl-utils/generate-key-pair keylength)]
     {:public-key (ssl-utils/get-public-key keypair)
      :private-key (ssl-utils/get-private-key keypair)
      :x500-name (ssl-utils/cn certname)
      :certname certname})))

(schema/defn ^:always-validate gen-cert* :- X509Certificate
  "Internal helper function to generate a certificate; see `gen-cert' for the
   public version of this function.
   An optional map may be provided to specify:

   * :extensions  List of certificate extensions to include on the certificate;
                  defaults to []."
  ([ca-keys host-keys serial] (gen-cert* ca-keys host-keys serial {}))
  ([ca-keys host-keys serial options] (gen-cert* ca-keys host-keys serial options false))
  ([ca-keys :- (schema/conditional
                (fn [cert] (some #(= :cert %) (keys cert))) SSLCert
                :else SSLKeyPair)
    host-keys :- SSLKeyPair
    serial :- schema/Int
    options :- SSLOptions
    ca? :- schema/Bool]
   (let [validity (cert-validity-dates (* 5 60 60 24 365))
         extensions (if ca?
                      (ssl-utils/create-ca-extensions
                        (:x509-name host-keys)
                        serial
                        (:public-key host-keys))
                      (get options :extensions []))]
     (ssl-utils/sign-certificate
      (:x500-name ca-keys)
      (:private-key ca-keys)
      serial
      (:not-before validity)
      (:not-after validity)
      (:x500-name host-keys)
      (:public-key host-keys)
      extensions))))

(schema/defn ^:always-validate gen-cert :- SSLCert
  "Generate a certificate. An optional map may be provided to specify:

   * :keylength   Bit length to use for the public/private keys;
                  defaults to 4096.
   * :extensions  List of certificate extensions to include on the certificate;
                  defaults to []."
  ([certname ca-cert serial] (gen-cert certname ca-cert serial {}))
  ([certname ca-cert serial options] (gen-cert certname ca-cert serial options false))
  ([certname :- schema/Str
    ca-cert :- SSLCert
    serial :- schema/Int
    options :- SSLOptions
    ca? :- schema/Bool]
   (let [cert-keys (gen-keys certname options)]
     (assoc cert-keys :cert (gen-cert* ca-cert cert-keys serial options ca?)))))

(schema/defn ^:always-validate gen-self-signed-cert :- SSLCert
  "Generate a self-signed certificate.
   An optional map may be provided to specify:

   * :keylength   Bit length to use for the public/private keys;
                  defaults to 4096.
   * :extensions  List of certificate extensions to include on the certificate;
                  defaults to []."
  ([certname serial] (gen-self-signed-cert certname serial {}))
  ([certname serial options] (gen-self-signed-cert certname serial options false))
  ([certname :- schema/Str
    serial :- schema/Int
    options :- SSLOptions
    ca? :- schema/Bool]
   (let [cert-keys (gen-keys certname options) ]
     (assoc cert-keys :cert (gen-cert* cert-keys cert-keys serial options ca?)))))

(schema/defn ^:always-validate gen-crl :- X509CRL
  [ca-cert :- SSLCert]
  (ssl-utils/generate-crl
    (.getIssuerX500Principal (:cert ca-cert))
    (:private-key ca-cert)
    (:public-key ca-cert)))
