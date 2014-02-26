(ns puppetlabs.jvm.certificate-authority.core-test
  (:import java.util.Arrays
           (java.security KeyPair KeyStore PublicKey PrivateKey SignatureException)
           (javax.security.auth.x500 X500Principal)
           (javax.net.ssl SSLContext)
           (java.security.cert X509Certificate X509CRL)
           (java.io ByteArrayOutputStream ByteArrayInputStream)
           (org.bouncycastle.asn1.x500 X500Name)
           (org.bouncycastle.pkcs PKCS10CertificationRequest))
  (:require [clojure.test :refer :all]
            [clojure.java.io :refer [resource reader]]
            [puppetlabs.jvm.certificate-authority.core :refer :all]))

(defn open-ssl-file
  [filepath]
  (resource (str "puppetlabs/jvm/certificate_authority/examples/ssl/" filepath)))

(defn write-to-pem-stream
  [object]
  (let [pem-stream (ByteArrayOutputStream.)]
    (obj->pem! object pem-stream)
    (-> pem-stream
        (.toByteArray)
        (ByteArrayInputStream.))))


(deftest key-test
  (testing "generate public & private keys"
    (let [key-pair (generate-key-pair)
          public   (.getPublic key-pair)
          private  (.getPrivate key-pair)]
      (is (instance? KeyPair key-pair))
      (is (instance? PublicKey public))
      (is (instance? PrivateKey private))))

  (testing "read single private key from PEM stream"
    (let [pem         (open-ssl-file "private_keys/localhost.pem")
          private-key (pem->private-key pem)]
      (is (instance? PrivateKey private-key)))

    (testing "throws exception if multiple keys found"
      (let [pem (open-ssl-file "private_keys/multiple_pks.pem")]
        (is (thrown-with-msg? IllegalArgumentException
                              #"The PEM stream must contain exactly one private key"
                              (pem->private-key pem))))))

  (testing "read multiple private keys from PEM stream"
    (let [pem          (open-ssl-file "private_keys/multiple_pks.pem")
          private-keys (pem->private-keys pem)]
      (is (= 2 (count private-keys)))
      (is (every? #(instance? PrivateKey %) private-keys))))

  (testing "write private key to PEM stream"
    (let [original-key (.getPrivate (generate-key-pair))
          pem-stream   (write-to-pem-stream original-key)
          parsed-key   (pem->private-key pem-stream)]
      (is (instance? PrivateKey parsed-key))
      (is (= original-key parsed-key))))

  (testing "read RSA-only keys from PEM stream"
    (let [rsa-only-keys (-> "private_keys/keyonly.pem" open-ssl-file pem->private-keys)]
      (is (every? #(instance? PrivateKey %) rsa-only-keys)))))


(deftest name-test
  (testing "create X500 name from common name"
    (let [x500-name   (generate-x500-name "common name")
          common-name (x500-name->CN x500-name)]
      (is (instance? X500Name x500-name))
      (is (= "common name" common-name)))))


(deftest certification-request-test
  (testing "create CSR"
    (let [key-pair     (generate-key-pair)
          subject-name (generate-x500-name "subject")
          csr          (generate-certificate-request key-pair subject-name)
          csr-subject  (.getSubject csr)]
      (is (instance? PKCS10CertificationRequest csr))
      (is (= subject-name csr-subject))))

  (testing "sign CSR"
    (let [csr         (generate-certificate-request
                        (generate-key-pair)
                        (generate-x500-name "foo"))
          issuer      (generate-x500-name "my ca")
          serial      42
          issuer-key  (.getPrivate (generate-key-pair))
          certificate (sign-certificate-request csr issuer serial issuer-key)]
      (is (instance? X509Certificate certificate))
      (is (= "CN=foo" (-> certificate .getSubjectX500Principal .getName)))
      (is (= "CN=my ca" (-> certificate .getIssuerX500Principal .getName)))
      (is (= 42 (-> certificate .getSerialNumber)))))

  (testing "read CSR from PEM stream"
    (let [pem      (open-ssl-file "certification_requests/ca_test_client.pem")
          csr      (pem->csr pem)
          expected (generate-x500-name "ca_test_client")]
      (is (instance? PKCS10CertificationRequest csr))
      (is (= expected (.getSubject csr))))

    (testing "throws exception if multiples found"
      (is (thrown-with-msg? IllegalArgumentException
                            #"The PEM stream contains more than one object"
                            (-> "certs/multiple.pem" open-ssl-file pem->csr)))))

  (testing "write CSR to PEM stream"
    (let [subject-name (generate-x500-name "foo")
          orig-csr     (generate-certificate-request (generate-key-pair) subject-name)
          pem          (write-to-pem-stream orig-csr)
          parsed-csr   (pem->csr pem)]
      (is (instance? PKCS10CertificationRequest parsed-csr))
      (is (= subject-name (.getSubject parsed-csr)))
      (is (= orig-csr parsed-csr)))))


(deftest certificate-test
  (testing "read certificates from PEM stream"
    (let [pem   (open-ssl-file "certs/multiple.pem")
          certs (pem->certs pem)]
      (is (= 2 (count certs)))
      (doseq [[actual expected] [[(first certs)
                                  {:subject-name "CN=Puppet CA: explosivo"
                                   :issuer-name "CN=Puppet CA: explosivo"
                                   :serial 1
                                   :version 3}]
                                 [(second certs)
                                  {:subject-name "CN=localhost"
                                   :issuer-name "CN=Puppet CA: explosivo"
                                   :serial 3
                                   :version 3}]]]
        (is (instance? X509Certificate actual))
        (let [subject-name (-> actual .getSubjectX500Principal .getName)
              issuer-name  (-> actual .getIssuerX500Principal .getName)
              serial       (-> actual .getSerialNumber)
              version      (-> actual .getVersion)]
          (is (= (expected :subject-name) subject-name))
          (is (= (expected :issuer-name) issuer-name))
          (is (= (expected :serial) serial))
          (is (= (expected :version) version))))))

  (testing "write certificate to PEM stream"
    (let [csr         (generate-certificate-request (generate-key-pair)
                                                    (generate-x500-name "foo"))
          orig-cert   (sign-certificate-request csr
                                                (generate-x500-name "my ca")
                                                42
                                                (.getPrivate (generate-key-pair)))
          pem         (write-to-pem-stream orig-cert)
          parsed-cert (first (pem->certs pem))]
      (is (instance? X509Certificate parsed-cert))
      (is (= "CN=foo" (-> parsed-cert .getSubjectX500Principal .getName)))
      (is (= "CN=my ca" (-> parsed-cert .getIssuerX500Principal .getName)))
      (is (= 42 (-> parsed-cert .getSerialNumber)))
      (is (= orig-cert parsed-cert)))))


(deftest certificate-revocation-list
  (testing "create CRL"
    (let [key-pair    (generate-key-pair)
          public-key  (.getPublic key-pair)
          private-key (.getPrivate key-pair)
          issuer-name "CN=my ca"
          crl         (generate-crl (X500Principal. issuer-name) private-key)]
      (is (instance? X509CRL crl))
      (is (= issuer-name (-> crl .getIssuerX500Principal .getName)))
      (is (nil? (.verify crl public-key)))
      (is (thrown? SignatureException
                   (.verify crl (.getPublic (generate-key-pair))))))))


(deftest keystore-test
  (testing "create keystore"
    (is (instance? KeyStore (keystore))))

  (testing "associate certificates from PEM stream"
    (let [pem            (open-ssl-file "certs/multiple.pem")
          keystore       (keystore)
          expected-certs (pem->certs pem)]
      (assoc-certs-from-reader! keystore "foobar" pem)
      (is (= 2 (.size keystore)))
      (is (.containsAlias keystore "foobar-0"))
      (is (.containsAlias keystore "foobar-1"))
      (is (= (first expected-certs) (.getCertificate keystore "foobar-0")))
      (is (= (second expected-certs) (.getCertificate keystore "foobar-1")))))

  (testing "associate private keys from PEM stream"
    (let [private-key-file (open-ssl-file "private_keys/localhost.pem")
          cert-file        (open-ssl-file "certs/localhost.pem")
          keystore         (keystore)
          _                (assoc-private-key-reader! keystore "mykey" private-key-file "bunkpassword" cert-file)
          keystore-key     (.getKey keystore "mykey" (char-array "bunkpassword"))]

      (testing "key read from keystore should match key read from PEM"
        (let [private-key (pem->private-key private-key-file)]
          (is (Arrays/equals (.getEncoded private-key) (.getEncoded keystore-key)))))

      (testing "PEM created from keystore should match original PEM"
        (let [stream       (ByteArrayOutputStream.)
              _            (key->pem! keystore-key stream)
              orig-pem     (.toByteArray stream)
              keystore-pem (-> private-key-file reader slurp .getBytes)]
          (is (Arrays/equals orig-pem keystore-pem)))))

    (testing "should fail when loading compound keys"
      (let [key      (open-ssl-file "private_keys/multiple_pks.pem")
            cert     (open-ssl-file "certs/localhost.pem")
            keystore (keystore)]
        (is (thrown-with-msg? IllegalArgumentException
                              #"The PEM stream must contain exactly one private key"
                              (assoc-private-key-reader! keystore "foo" key "foo" cert)))))

    (testing "should fail when multiple certs found"
      (let [key      (open-ssl-file "private_keys/localhost.pem")
            cert     (open-ssl-file "certs/multiple.pem")
            keystore (keystore)]
        (is (thrown-with-msg? IllegalArgumentException
                              #"The PEM stream contains more than one certificate"
                              (assoc-private-key-reader! keystore "foo" key "foo" cert))))))

  (testing "convert PEMs to keystore/truststore"
    (let [result (pems->key-and-trust-stores
                   (open-ssl-file "certs/localhost.pem")
                   (open-ssl-file "private_keys/localhost.pem")
                   (open-ssl-file "certs/ca.pem"))]
      (is (map? result))
      (is (= #{:keystore :keystore-pw :truststore} (-> result keys set)))
      (is (instance? KeyStore (:keystore result)))
      (is (instance? KeyStore (:truststore result)))
      (is (string? (:keystore-pw result))))))


(deftest ssl-context-test
  (testing "convert PEMs to SSLContext"
    (let [result (pems->ssl-context
                   (open-ssl-file "certs/localhost.pem")
                   (open-ssl-file "private_keys/localhost.pem")
                   (open-ssl-file "certs/ca.pem"))]
      (is (instance? SSLContext result)))))
