(ns puppetlabs.ssl-utils.testutils
  (:import (java.io ByteArrayOutputStream ByteArrayInputStream)
           (java.security.cert X509Certificate)
           (java.security MessageDigest)
           (org.bouncycastle.asn1.x500 X500Name)
           (org.bouncycastle.pkcs PKCS10CertificationRequest)
           (org.joda.time DateTime Period)
           (org.bouncycastle.asn1.x509 SubjectPublicKeyInfo))
  (:require [clojure.test :refer :all]
            [clojure.java.io :refer [resource reader]]
            [puppetlabs.ssl-utils.core :refer :all]))

(defn pubkey-sha1
  "Gets the SHA-1 digest of the raw bytes of the provided publickey."
  [pub-key]
  {:pre [(public-key? pub-key)]
   :post [(vector? %)
          (every? integer? %)]}
  (let [bytes   (-> pub-key
                    .getEncoded
                    SubjectPublicKeyInfo/getInstance
                    .getPublicKeyData
                    .getBytes)]
    (vec (.digest (MessageDigest/getInstance "SHA1") bytes))))

(defn open-ssl-file
  [filepath]
  (resource (str "puppetlabs/ssl_utils/examples/ssl/" filepath)))

(defn write-to-pem-stream
  ([object] (write-to-pem-stream object obj->pem!))
  ([object write-function]
   (let [pem-stream (ByteArrayOutputStream.)]
     (write-function object pem-stream)
     (-> pem-stream
         (.toByteArray)
         (ByteArrayInputStream.)))))

(defmulti has-subject?
          "Returns true if x has the subject identified by the x500-name string or `X500Name`.
          Default implementations are provided for `X509Certificate` and `PKCS10CertificationRequest`."
          (fn [x x500-name]
            [(class x) (class x500-name)]))

(defmethod has-subject? [X509Certificate String]
  [cert x500-name]
  (= x500-name (-> cert .getSubjectX500Principal .getName)))

(defmethod has-subject? [X509Certificate X500Name]
  [cert x500-name]
  (has-subject? cert (str x500-name)))

(defmethod has-subject? [PKCS10CertificationRequest String]
  [csr x500-name]
  (= x500-name (-> csr .getSubject str)))

(defmethod has-subject? [PKCS10CertificationRequest X500Name]
  [csr x500-name]
  (= x500-name (.getSubject csr)))

(defmulti issued-by?
          "Returns true if x was issued by the x500-name string or `X500Name`.
          Default implementations are provided for `X509Certificate` and `X509CRL`."
          (fn [_ x500-name]
            (class x500-name)))

(defmethod issued-by? String
  [x x500-name]
  (= x500-name (-> x .getIssuerX500Principal .getName)))

(defmethod issued-by? X500Name
  [x x500-name]
  (issued-by? x (str x500-name)))

(defn generate-not-before-date []
  (-> (DateTime/now)
      (.minus (Period/days 1))
      (.toDate)))

(defn generate-not-after-date []
  (-> (DateTime/now)
      (.plus (Period/years 5))
      (.toDate)))

(defn str->bytes
  "Turn a `String s` into `bytes[]`"
  [^String s]
  (bytes (byte-array (map (comp byte int) s))))