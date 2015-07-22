(ns puppetlabs.ssl-utils.simple
  (:import (java.util Date))
  (:require [puppetlabs.ssl-utils.core :as ssl-utils]
            [clj-time.core :as time]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Predicates

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

(defn cert-validity-dates
  "Calculate the not-before & not-after dates that define a certificate's
   period of validity. The value of `ca-ttl` is expected to be in seconds,
   and the dates will be based on the current time. Returns a map in the
   form {:not-before Date :not-after Date}."
  [ca-ttl]
  {:pre [(integer? ca-ttl)]
   :post [(validity-date-range? %)]}
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

(defn gen-keys
  "Generate public and private keys and the X500 name for the given `certname'.
   An optional map may be provided to specify:

   * :keylength  Bit length to use for the public/private keys;
                 defaults to 4096."
  ([certname] (gen-keys certname {}))
  ([certname options]
   {:pre [(string? certname)
          (map? options)]
    :post [(ssl-keys? %)]}
   (let [keylength (get options :keylength default-keylength)
         keypair (ssl-utils/generate-key-pair keylength)]
     {:public-key (ssl-utils/get-public-key keypair)
      :private-key (ssl-utils/get-private-key keypair)
      :x500-name (ssl-utils/cn certname)
      :certname certname})))

(defn gen-cert*
  "Internal helper function to generate a certificate; see `gen-cert' for the
   public version of this function.
   An optional map may be provided to specify:

   * :extensions  List of certificate extensions to include on the certificate;
                  defaults to []."
  ([ca-keys host-keys serial] (gen-cert* ca-keys host-keys serial {}))
  ([ca-keys host-keys serial options]
   {:pre [(ssl-keys? ca-keys)
          (ssl-keys? host-keys)
          (integer? serial)
          (map? options)]
    :post [(ssl-utils/certificate? %)]}
   (let [validity (cert-validity-dates (* 5 60 60 24 365))
         extensions (get options :extensions [])]
     (ssl-utils/sign-certificate
      (:x500-name ca-keys)
      (:private-key ca-keys)
      serial
      (:not-before validity)
      (:not-after validity)
      (:x500-name host-keys)
      (:public-key host-keys)
      extensions))))

(defn gen-cert
  "Generate a certificate. An optional map may be provided to specify:

   * :keylength   Bit length to use for the public/private keys;
                  defaults to 4096.
   * :extensions  List of certificate extensions to include on the certificate;
                  defaults to []."
  ([certname ca-cert serial] (gen-cert certname ca-cert serial {}))
  ([certname ca-cert serial options]
   {:pre [(string? certname)
          (ssl-cert? ca-cert)
          (integer? serial)
          (map? options)]
    :post [(ssl-cert? %)]}
   (let [cert-keys (gen-keys certname options)]
     (assoc cert-keys :cert (gen-cert* ca-cert cert-keys serial options)))))

(defn gen-self-signed-cert
  "Generate a self-signed certificate.
   An optional map may be provided to specify:

   * :keylength   Bit length to use for the public/private keys;
                  defaults to 4096.
   * :extensions  List of certificate extensions to include on the certificate;
                  defaults to []."
  ([certname serial] (gen-self-signed-cert certname serial {}))
  ([certname serial options]
   {:pre [(string? certname)
          (integer? serial)
          (map? options)]
    :post [(ssl-cert? %)]}
   (let [cert-keys (gen-keys certname options)]
     (assoc cert-keys :cert (gen-cert* cert-keys cert-keys serial options)))))

(defn gen-crl
  [ca-cert]
  {:pre [(ssl-cert? ca-cert)]
   :post [(ssl-utils/certificate-revocation-list? %)]}
  (ssl-utils/generate-crl
    (.getIssuerX500Principal (:cert ca-cert))
    (:private-key ca-cert)
    (:public-key ca-cert)))
