(ns puppetlabs.ssl-utils.simple-test
  (:require [clojure.test :refer :all]
            [puppetlabs.ssl-utils.simple :as simple]
            [puppetlabs.ssl-utils.core :as ssl-utils])
  (:import (java.io ByteArrayOutputStream ByteArrayInputStream)))

(defn roundtrip-pem
  [to-pem-fn from-pem-fn obj]
  (let [outstream (ByteArrayOutputStream.)]
    (to-pem-fn obj outstream)
    (let [instream (ByteArrayInputStream. (.toByteArray outstream))]
      (from-pem-fn instream))))

(deftest basic-ca-cert-crl-test
  (testing "Can generate a valid CA cert, cert, and CRL through simple API"
    (let [ca-cert (simple/gen-self-signed-cert "ca" 1)
          cert (simple/gen-cert "foo.localdomain" ca-cert 2)
          crl (simple/gen-crl ca-cert)
          read-ca-cert (roundtrip-pem ssl-utils/cert->pem! ssl-utils/pem->cert (:cert ca-cert))
          read-cert (roundtrip-pem ssl-utils/cert->pem! ssl-utils/pem->cert (:cert cert))
          read-crl (roundtrip-pem ssl-utils/crl->pem! ssl-utils/pem->crl crl)]
      (is (ssl-utils/certificate? read-ca-cert))
      (is (ssl-utils/certificate? read-cert))
      (is (ssl-utils/certificate-revocation-list? read-crl))
      (is (= "ca" (ssl-utils/get-cn-from-x509-certificate read-ca-cert)))
      (is (= "foo.localdomain" (ssl-utils/get-cn-from-x509-certificate read-cert)))
      (is (= "ca" (ssl-utils/get-cn-from-x500-principal (.getIssuerX500Principal read-cert))))
      (is (= "ca" (ssl-utils/get-cn-from-x500-principal (.getIssuerX500Principal read-crl)))))))
