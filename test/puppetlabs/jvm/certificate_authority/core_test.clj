(ns puppetlabs.jvm.certificate-authority.core-test
  (:import java.util.Arrays
           (java.security KeyPair KeyStore PublicKey PrivateKey SignatureException)
           (javax.security.auth.x500 X500Principal)
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
                              #"The PEM file .* must contain exactly one private key"
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
          certificate (sign-certificate-request
                        csr
                        (generate-x500-name "my ca")
                        42
                        (.getPrivate (generate-key-pair)))]
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
                            #"The PEM file .* contains more than one object"
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
            cert     (open-ssl-file "certs/multiple.pem")
            keystore (keystore)]
        (is (thrown? IllegalArgumentException
                     (assoc-private-key-reader! keystore "foo" key "foo" cert)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; Tests from Chris' branch

(defn to-pem-stream
  [obj]
  (let [bs (ByteArrayOutputStream.)]
    (obj->pem! obj bs)
    (ByteArrayInputStream. (.toByteArray bs))))

(defn to-pem-and-back
  [obj]
  (let [ps   (to-pem-stream obj)
        objs (pem->objs ps)]
    (assert (= 1 (count objs)))
    (first objs)))

(deftest keypair-test
  (testing "can create keypair"
    (let [kp (generate-key-pair)]
      (is (instance? KeyPair kp))
      (let [obj      (to-pem-and-back kp)
            priv-key (obj->private-key obj)]
        (is (instance? PrivateKey priv-key))))))

(deftest x500-name-test
  (testing "can create x500 name"
    (let [x500-name (generate-x500-name "foo")]
      (is (instance? X500Name x500-name))
      (is (= "foo" (x500-name->CN x500-name))))))

(deftest csr-test
  (testing "can create a CSR"
    (let [n   (generate-x500-name "foo")
          kp  (generate-key-pair)
          csr (generate-certificate-request kp n)]
      (is (instance? PKCS10CertificationRequest csr))
      (let [obj (to-pem-and-back csr)]
        (is (instance? PKCS10CertificationRequest obj)))))

  (testing "can write and read a CSR from a pem"
    (let [n   (generate-x500-name "foo")
          kp  (generate-key-pair)
          csr (generate-certificate-request kp n)
          ps  (to-pem-stream csr)]
      (is (instance? PKCS10CertificationRequest (pem->csr ps))))))

(deftest cert-test
  (testing "can sign a cert"
    (let [n              (generate-x500-name "foo")
          kp             (generate-key-pair)
          csr            (generate-certificate-request kp n)
          ca-name        (generate-x500-name "My First CA")
          ca-private-key (.getPrivate (generate-key-pair))
          serial         42
          cert           (sign-certificate-request csr ca-name serial ca-private-key)]
      (is (instance? X509Certificate cert))
      (let [ps    (to-pem-stream cert)
            certs (pem->certs ps)]
        (is (= 1 (count certs)))
        (is (instance? X509Certificate (first certs)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; SSL tests from Kitchensink below

(deftest privkeys
  (testing "assoc-private-key-reader!"
    (let [private-key-file (open-ssl-file "private_keys/localhost.pem")
          cert-file        (open-ssl-file "certs/localhost.pem")
          keystore         (keystore)
          _                (assoc-private-key-reader! keystore "mykey" private-key-file "bunkpassword" cert-file)
          keystore-key     (.getKey keystore "mykey" (char-array "bunkpassword"))
          private-key      (first (pem->private-keys private-key-file))]

      (testing "key read from keystore should match key read from pem"
        (is (Arrays/equals (.getEncoded private-key) (.getEncoded keystore-key))))

      (testing "pem created from keystore should match original pem file"
        (let [pem-writer-stream   (java.io.ByteArrayOutputStream.)
              _                   (key->pem! keystore-key pem-writer-stream)]
          (is (Arrays/equals (-> (reader private-key-file)
                                 (slurp)
                                 (.getBytes))
                             (.toByteArray pem-writer-stream))))))))

(deftest multiple-objs
  (testing "loading a PEM file with multiple keys"
    (let [pem (open-ssl-file "private_keys/multiple_pks.pem")]
      (testing "should return multiple keys"
        (is (= 2 (count (pem->private-keys pem)))))))

  (testing "loading compound keys files into a keystore should fail"
    (let [key  (open-ssl-file "private_keys/multiple_pks.pem")
          cert (open-ssl-file "certs/multiple.pem")
          ks   (keystore)]
      (is (thrown? IllegalArgumentException
                   (assoc-private-key-reader! ks "foo" key "foo" cert)))))

  (testing "loading a PEM file with multiple certs"
    (let [pem (open-ssl-file "certs/multiple.pem")]
      (testing "should return multiple certs"
        (is (= 2 (count (pem->certs pem)))))

      (testing "should load all certs from the file into a keystore"
        (let [ks (keystore)]
          (assoc-certs-from-reader! ks "foobar" pem)
          (is (= 2 (.size ks)))
          (is (.containsAlias ks "foobar-0"))
          (is (.containsAlias ks "foobar-1")))))))

(deftest rsakeyonly
  (testing "reading PEM files with only the RSA-key should work"
    (let [privkey (open-ssl-file "private_keys/keyonly.pem")]
      (is (every? #(instance? PrivateKey %) (pem->private-keys privkey))))))
