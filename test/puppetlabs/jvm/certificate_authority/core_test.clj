(ns puppetlabs.jvm.certificate-authority.core-test
  (:import java.util.Arrays
           (java.security KeyPair PrivateKey)
           (java.security.cert X509Certificate)
           (java.io ByteArrayOutputStream ByteArrayInputStream)
           (org.bouncycastle.asn1.x500 X500Name)
           (org.bouncycastle.pkcs PKCS10CertificationRequest))
  (:require [clojure.test :refer :all]
            [clojure.java.io :refer [resource reader]]
            [puppetlabs.jvm.certificate-authority.core :refer :all]))

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
        (is (instance? PKCS10CertificationRequest obj))))))

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
      (let [ps (to-pem-stream cert)
            certs (pem->certs ps)]
        (is (= 1 (count certs)))
        (is (instance? X509Certificate (first certs)))))))

;;;; SSL tests from Kitchensink below

(defn ssl-dir
  [sub-path]
  (str "puppetlabs/jvm/certificate_authority/examples/ssl/" sub-path))

(deftest privkeys
  (testing "assoc-private-key-reader!"
    (let [private-key-file (resource (ssl-dir "private_keys/localhost.pem"))
          cert-file        (resource (ssl-dir "certs/localhost.pem"))
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
    (let [pem (resource (ssl-dir "private_keys/multiple_pks.pem"))]
      (testing "should return multiple keys"
        (is (= 2 (count (pem->private-keys pem)))))))

  (testing "loading compound keys files into a keystore should fail"
    (let [key  (resource (ssl-dir "private_keys/multiple_pks.pem"))
          cert (resource (ssl-dir "certs/multiple.pem"))
          ks   (keystore)]
      (is (thrown? IllegalArgumentException
                   (assoc-private-key-reader! ks "foo" key "foo" cert)))))

  (testing "loading a PEM file with multiple certs"
    (let [pem (resource (ssl-dir "certs/multiple.pem"))]
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
    (let [privkey (resource (ssl-dir "private_keys/keyonly.pem"))]
            (is (every? #(instance? PrivateKey %) (pem->private-keys privkey))))))
