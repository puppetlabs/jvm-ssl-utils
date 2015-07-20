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

(def key-length 4096)

;; TODO Add final optional `options' map for :key-length
(defn gen-keys
  [certname]
  {:pre [(string? certname)]
   :post [(ssl-keys? %)]}
  (let [keypair     (ssl-utils/generate-key-pair key-length)]
    {:public-key (ssl-utils/get-public-key keypair)
     :private-key (ssl-utils/get-private-key keypair)
     :x500-name (ssl-utils/cn certname)
     :certname certname}))

;; TODO Add final optional `options' map for :extensions
(defn gen-cert*
  [ca-keys host-keys serial]
  {:pre [(ssl-keys? ca-keys)
         (ssl-keys? host-keys)
         (integer? serial)]
   :post [(ssl-utils/certificate? %)]}
  (let [validity (cert-validity-dates (* 5 60 60 24 365))]
    (ssl-utils/sign-certificate
      (:x500-name ca-keys)
      (:private-key ca-keys)
      serial
      (:not-before validity)
      (:not-after validity)
      (:x500-name host-keys)
      (:public-key host-keys)
      [])))

;; TODO Add final optional `options' map for :key-length and :extensions
(defn gen-cert
  [certname ca-cert serial]
  {:pre [(string? certname)
         (ssl-cert? ca-cert)
         (integer? serial)]
   :post [(ssl-cert? %)]}
  (let [cert-keys (gen-keys certname)]
    (assoc cert-keys :cert (gen-cert* ca-cert cert-keys serial))))

;; TODO Add final optional `options' map for :key-length and :extensions
(defn gen-self-signed-cert
  [certname serial]
  {:pre [(string? certname)
         (integer? serial)]
   :post [(ssl-cert? %)]}
  (let [cert-keys (gen-keys certname)]
    (assoc cert-keys :cert (gen-cert* cert-keys cert-keys serial))))

(defn gen-crl
  [ca-cert]
  {:pre [(ssl-cert? ca-cert)]
   :post [(ssl-utils/certificate-revocation-list? %)]}
  (ssl-utils/generate-crl
    (.getIssuerX500Principal (:cert ca-cert))
    (:private-key ca-cert)
    (:public-key ca-cert)))

