(ns puppetlabs.certificate-authority.core-test
  (:import java.util.Arrays
           (java.io ByteArrayOutputStream ByteArrayInputStream)
           (java.security.cert X509Certificate)
           (java.security KeyStore SignatureException MessageDigest)
           (javax.security.auth.x500 X500Principal)
           (javax.net.ssl SSLContext)
           (org.bouncycastle.asn1.x500 X500Name)
           (org.bouncycastle.pkcs PKCS10CertificationRequest)
           (org.joda.time DateTime Period)
           (org.bouncycastle.asn1.x509 SubjectPublicKeyInfo))
  (:require [clojure.test :refer :all]
            [clojure.java.io :refer [resource reader]]
            [puppetlabs.certificate-authority.core :refer :all]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Utilities

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
  (resource (str "puppetlabs/certificate_authority/examples/ssl/" filepath)))

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Tests

(deftest key-test
  (testing "generate public & private keys"
    (let [key-pair (generate-key-pair)
          public   (get-public-key key-pair)
          private  (get-private-key key-pair)]
      (is (keypair? key-pair))
      (is (public-key? public))
      (is (private-key? private))))

  (testing "keylength"
    (doseq [[test-str keypair expected-length]
            [["defaults to 4096" (generate-key-pair)      4096]
             ["is configurable"  (generate-key-pair 1024) 1024]]]
      (testing test-str
        (let [public-length  (-> keypair get-public-key keylength)
              private-length (-> keypair get-private-key keylength)]
          (is (= expected-length public-length))
          (is (= expected-length private-length))))))

  (testing "read public key from PEM stream"
    (let [public-key (-> "public_keys/localhost.pem"
                         open-ssl-file
                         pem->public-key)]
      (is (public-key? public-key))))

  (testing "write public key to PEM stream"
    (let [original-key (get-public-key (generate-key-pair 512))
          parsed-key   (-> original-key
                           (write-to-pem-stream key->pem!)
                           pem->public-key)]
      (is (public-key? parsed-key))
      (is (= original-key parsed-key))))

  (testing "read single private key from PEM stream"
    (let [private-key (-> "private_keys/localhost.pem"
                          open-ssl-file
                          pem->private-key)]
      (is (private-key? private-key)))

    (testing "throws exception if multiple keys found"
      (let [pem (open-ssl-file "private_keys/multiple_pks.pem")]
        (is (thrown-with-msg? IllegalArgumentException
                              #"The PEM stream must contain exactly one private key"
                              (pem->private-key pem))))))

  (testing "read multiple private keys from PEM stream"
    (let [pem          (open-ssl-file "private_keys/multiple_pks.pem")
          private-keys (pem->private-keys pem)]
      (is (= 2 (count private-keys)))
      (is (every? private-key? private-keys))))

  (testing "write private key to PEM stream"
    (let [original-key (get-private-key (generate-key-pair 512))
          parsed-key   (-> original-key
                           (write-to-pem-stream key->pem!)
                           pem->private-key)]
      (is (private-key? parsed-key))
      (is (= original-key parsed-key))))

  (testing "read RSA-only keys from PEM stream"
    (let [rsa-only-keys (-> "private_keys/keyonly.pem" open-ssl-file pem->private-keys)]
      (is (every? private-key? rsa-only-keys)))))


(deftest name-test
  (testing "create X500 name from common name"
    (let [x500-name (cn "common name")
          common-name (x500-name->CN x500-name)]
      (is (valid-x500-name? x500-name))
      (is (= "common name" common-name)))))

(deftest cn-from-x500principal-test
  (testing "cn extracted from an X500Principal"
    (let [x500-principal (X500Principal.
                           "CN=myagent, OU=Users, OU=Department A, DC=mydomain, DC=com")
          cn (get-cn-from-x500-principal x500-principal)]
      (is (= "myagent" cn)))))

(deftest certification-request-test
  (testing "create CSR"
    (let [subject (cn "subject")
          csr     (generate-certificate-request (generate-key-pair) subject)]
      (is (certificate-request? csr))
      (is (has-subject? csr subject))))

  (testing "read CSR from PEM stream"
    (let [pem (open-ssl-file "certification_requests/ca_test_client.pem")
          csr (pem->csr pem)]
      (is (certificate-request? csr))
      (is (has-subject? csr "CN=ca_test_client"))))

    (testing "throws exception if multiples found"
      (is (thrown-with-msg? IllegalArgumentException
                            #"The PEM stream contains more than one object"
                            (-> "certs/multiple.pem" open-ssl-file pem->csr)))))

  (testing "write CSR to PEM stream"
    (let [subject    (cn "foo")
          orig-csr   (generate-certificate-request (generate-key-pair) subject)
          pem        (write-to-pem-stream orig-csr)
          parsed-csr (pem->csr pem)]
      (is (certificate-request? parsed-csr))
      (is (has-subject? parsed-csr subject))
      (is (= orig-csr parsed-csr))))

(deftest signing-certificates
  (let [subject         (cn "foo")
        key-pair        (generate-key-pair)
        subj-pub        (get-public-key key-pair)
        issuer          (cn "my ca")
        issuer-key-pair (generate-key-pair)
        issuer-priv     (get-private-key issuer-key-pair)
        issuer-pub      (get-public-key issuer-key-pair)
        not-before      (generate-not-before-date)
        not-after       (generate-not-after-date)]
    (testing "sign certificate"
      (let [certificate (sign-certificate issuer issuer-priv 42 not-before not-after
                                          subject subj-pub)]
        (is (certificate? certificate))
        (is (has-subject? certificate subject))
        (is (issued-by? certificate issuer))
        (is (= (.getSerialNumber certificate) 42))))

    (testing "signing extensions into certificate"
      (let [sign-exts     [(puppet-node-uid
                             "ED803750-E3C7-44F5-BB08-41A04433FE2E" false)
                           (puppet-node-instance-id
                             "1234567890" false)
                           (puppet-node-image-name
                             "my_ami_image" false)
                           (puppet-node-preshared-key
                             "342thbjkt82094y0uthhor289jnqthpc2290" false)
                           (netscape-comment
                             "Puppet JVM Internal Certificate")
                           (authority-key-identifier
                             issuer-pub false)
                           (basic-constraints
                             false nil true)
                           (ext-key-usages
                             ["1.3.6.1.5.5.7.3.1" "1.3.6.1.5.5.7.3.2"] true)
                           (key-usage
                             #{:key-encipherment :digital-signature} true)
                           (subject-key-identifier
                             subj-pub false)
                           (subject-dns-alt-names
                             ["onefish" "twofish"] false)]
            expected-exts [{:oid      "1.3.6.1.4.1.34380.1.1.1"
                            :critical false
                            :value    "ED803750-E3C7-44F5-BB08-41A04433FE2E"}
                           {:oid      "1.3.6.1.4.1.34380.1.1.2"
                            :critical false
                            :value    "1234567890"}
                           {:oid      "1.3.6.1.4.1.34380.1.1.3"
                            :critical false
                            :value    "my_ami_image"}
                           {:oid      "1.3.6.1.4.1.34380.1.1.4"
                            :critical false
                            :value    "342thbjkt82094y0uthhor289jnqthpc2290"}
                           {:oid      "2.16.840.1.113730.1.13"
                            :critical false
                            :value    "Puppet JVM Internal Certificate"}
                            {:oid      "2.5.29.19"
                            :critical true
                            :value    {:is-ca false
                                       :path-len-constraint nil}}
                           {:oid      "2.5.29.37"
                            :critical true
                            :value    ["1.3.6.1.5.5.7.3.1" "1.3.6.1.5.5.7.3.2"]}
                           {:oid      "2.5.29.15"
                            :critical true
                            :value    #{:key-encipherment :digital-signature}}
                           {:oid      "2.5.29.17"
                            :critical false
                            :value    {:dns-name ["onefish" "twofish"]}}
                           {:oid      "2.5.29.14"
                            :value    (pubkey-sha1 subj-pub)
                            :critical false}
                           {:oid      "2.5.29.35"
                            :critical false
                            :value    {:issuer         nil
                                       :key-identifier (pubkey-sha1 issuer-pub)
                                       :serial-number  nil}}]
            cert-w-exts (sign-certificate issuer issuer-priv 42 not-before
                                          not-after subject subj-pub sign-exts)
            cert-exts   (get-extensions cert-w-exts)]
        (is (= (set cert-exts) (set expected-exts)))))))

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
        (is (certificate? actual))
        (is (has-subject? actual (expected :subject-name)))
        (is (issued-by? actual (expected :issuer-name)))
        (is (= (.getSerialNumber actual) (expected :serial)))
        (is (= (.getVersion actual) (expected :version))))))

  (testing "write certificate to PEM stream"
    (let [subject     (cn "foo")
          key-pair    (generate-key-pair 512)
          subj-pub    (get-public-key key-pair)
          issuer      (cn "my ca")
          issuer-key  (get-private-key (generate-key-pair))
          serial      42
          not-before  (generate-not-before-date)
          not-after   (generate-not-after-date)
          orig-cert   (sign-certificate issuer issuer-key serial not-before
                                        not-after subject subj-pub)
          pem         (write-to-pem-stream orig-cert cert->pem!)
          parsed-cert (pem->cert pem)]
      (is (certificate? parsed-cert))
      (is (has-subject? parsed-cert subject))
      (is (issued-by? parsed-cert issuer))
      (is (= (.getSerialNumber parsed-cert) serial))
      (is (= orig-cert parsed-cert)))))

(deftest certificate-revocation-list
  (let [key-pair    (generate-key-pair)
        public-key  (get-public-key key-pair)
        private-key (get-private-key key-pair)
        issuer-name (cn "my ca")
        crl         (generate-crl (X500Principal. issuer-name) private-key)]

    (testing "create CRL"
      (is (certificate-revocation-list? crl))
      (is (issued-by? crl issuer-name))
      (is (nil? (.verify crl public-key)))
      (is (thrown? SignatureException
                   (.verify crl (get-public-key (generate-key-pair))))))

    (testing "read CRL from PEM stream"
      (let [parsed-crl (-> "ca_crl.pem" open-ssl-file pem->crl)]
        (is (certificate-revocation-list? parsed-crl))
        (is (issued-by? parsed-crl "CN=Puppet CA: localhost"))))

    (testing "write CRL to PEM stream"
      (let [parsed-crl (-> crl (write-to-pem-stream crl->pem!) pem->crl)]
        (is (certificate-revocation-list? parsed-crl))
        (is (issued-by? parsed-crl issuer-name))
        (is (= crl parsed-crl))))))

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
          _                (assoc-private-key-from-reader! keystore "mykey" private-key-file "bunkpassword" cert-file)
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
                              (assoc-private-key-from-reader! keystore "foo" key "foo" cert)))))

    (testing "should fail when multiple certs found"
      (let [key      (open-ssl-file "private_keys/localhost.pem")
            cert     (open-ssl-file "certs/multiple.pem")
            keystore (keystore)]
        (is (thrown-with-msg? IllegalArgumentException
                              #"The PEM stream contains more than one certificate"
                              (assoc-private-key-from-reader! keystore "foo" key "foo" cert))))))

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
      (is (instance? SSLContext result))))
  (testing "convert CA cert PEM to SSLContext"
    (let [result (ca-cert-pem->ssl-context
                   (open-ssl-file "certs/ca.pem"))]
      (is (instance? SSLContext result)))))

(let [keypair (generate-key-pair 512)
      public (get-public-key keypair)
      private (get-private-key keypair)]

  (deftest keypair?-test
    (is (true? (keypair? keypair)))
    (is (false? (keypair? (str keypair))))
    (is (false? (keypair? public)))
    (is (false? (keypair? private)))
    (is (false? (keypair? "foo")))
    (is (false? (keypair? nil))))

  (deftest public-key?-test
    (is (true? (public-key? public)))
    (is (false? (public-key? (str public))))
    (is (false? (public-key? private)))
    (is (false? (public-key? "foo")))
    (is (false? (public-key? nil))))

  (deftest private-key?-test
    (is (true? (private-key? private)))
    (is (false? (private-key? (str private))))
    (is (false? (private-key? public)))
    (is (false? (private-key? "foo")))
    (is (false? (private-key? nil)))))

(let [subject (cn "subject")
      issuer  (cn "issuer")
      key-pair (generate-key-pair 512)
      csr     (generate-certificate-request key-pair subject)
      cert    (sign-certificate issuer (get-private-key (generate-key-pair 512))
                                42 (generate-not-before-date)
                                (generate-not-after-date) subject
                                (get-public-key (generate-key-pair 512)))
      crl     (generate-crl (X500Principal. (str issuer)) (get-private-key (generate-key-pair 512)))]

  (deftest getting-public-key
    (let [pub-key (get-public-key csr)]
      (is (= pub-key (get-public-key key-pair)))))

  (deftest valid-x500-name?-test
    (is (= "CN=common name" (dn [:cn "common name"])))
    (is (= "CN=cn,O=org" (dn [:cn "cn" :o "org"])))
    (is (thrown? AssertionError (dn [])))
    (is (thrown? AssertionError (dn [:cn :cn "cn"])))
    (is (true?  (valid-x500-name? subject)))
    (is (false? (valid-x500-name? "subject")))
    (is (false? (valid-x500-name? nil))))

  (deftest certificate-request?-test
    (is (true? (certificate-request? csr)))
    (is (false? (certificate-request? (str csr))))
    (is (false? (certificate-request? "foo")))
    (is (false? (certificate-request? nil))))

  (deftest certificate?-test
    (is (true? (certificate? cert)))
    (is (false? (certificate? (str cert))))
    (is (false? (certificate? csr)))
    (is (false? (certificate? "foo")))
    (is (false? (certificate? nil))))

  (deftest certificate-revocation-list?-test
    (is (true? (certificate-revocation-list? crl)))
    (is (false? (certificate-revocation-list? (str crl))))
    (is (false? (certificate-revocation-list? "foo")))
    (is (false? (certificate-revocation-list? nil))))

  (deftest has-subject?-test
    (testing "certificate signing request"
      (is (true? (has-subject? csr subject)))
      (is (true? (has-subject? csr (str subject))))
      (is (true? (has-subject? csr "CN=subject")))
      (is (true? (has-subject? csr (cn "subject"))))
      (is (false? (has-subject? csr "subject"))))

    (testing "certificate"
      (is (true? (has-subject? cert subject)))
      (is (true? (has-subject? cert (str subject))))
      (is (true? (has-subject? cert "CN=subject")))
      (is (true? (has-subject? cert (cn "subject"))))
      (is (false? (has-subject? cert "subject")))))

  (deftest issued-by?-test
    (testing "certificate"
      (is (true? (issued-by? cert issuer)))
      (is (true? (issued-by? cert (str issuer))))
      (is (true? (issued-by? cert "CN=issuer")))
      (is (true? (issued-by? cert (cn "issuer"))))
      (is (false? (issued-by? cert "issuer"))))

    (testing "certificate revocation list"
      (is (true? (issued-by? crl issuer)))
      (is (true? (issued-by? crl (str issuer))))
      (is (true? (issued-by? crl "CN=issuer")))
      (is (true? (issued-by? crl (cn "issuer"))))
      (is (false? (issued-by? crl "issuer")))))

  (deftest x500-name->CN-test
    (testing "getting CN from DN works"
      (is (= "subject" (x500-name->CN subject))))))

(deftest extensions
  (testing "Found all extensions from a certificate on disk."
    (let [cert       (-> "certs/cert-with-exts.pem"
                         open-ssl-file
                         pem->cert)
          extensions (get-extensions cert)]
      (is (= 10 (count extensions)))
      (doseq [[oid value]
              [["2.5.29.15" #{:key-encipherment :digital-signature}]
               ["2.5.29.19" {:is-ca               false
                             :path-len-constraint nil}]
               ["2.5.29.37" ["1.3.6.1.5.5.7.3.1" "1.3.6.1.5.5.7.3.2"]]
               ["1.3.6.1.4.1.34380.1.1.1" "ED803750-E3C7-44F5-BB08-41A04433FE2E"]
               ["1.3.6.1.4.1.34380.1.1.2" "1234567890"]
               ["1.3.6.1.4.1.34380.1.1.3" "my_ami_image"]
               ["1.3.6.1.4.1.34380.1.1.4" "342thbjkt82094y0uthhor289jnqthpc2290"]
               ["2.16.840.1.113730.1.13" "Puppet Ruby/OpenSSL Internal Certificate"]]]
        (is (= (get-extension-value extensions oid) value)))))

  (testing "Found all extensions from a cert request on disk."
    (let [csr (-> "certification_requests/ca_test_client_with_exts.pem"
                  open-ssl-file
                  pem->csr)
          extensions (get-extensions csr)]
      (is (= (set extensions)
             #{{:critical false,
                :oid "1.3.6.1.4.1.34380.1.1.1",
                :value "ED803750-E3C7-44F5-BB08-41A04433FE2E"}
               {:critical false,
                :oid "1.3.6.1.4.1.34380.1.1.3",
                :value "my_ami_image"}
               {:critical false,
                :oid "1.3.6.1.4.1.34380.1.1.4",
                :value "342thbjkt82094y0uthhor289jnqthpc2290"}
               {:critical false,
                :oid "1.3.6.1.4.1.34380.1.1.2",
                :value "1234567890"}}))))

  (testing "Testing OID subtree status"
    (is (subtree-of? "1.2.3.4"
                     "1.2.3.4.5"))
    (is (subtree-of? "1.2.3.4.5"
                     "1.2.3.4.5.6"))
    (is (not (subtree-of? "1.2.3.4"
                          "5.6.7.8")))
    (is (not (subtree-of? "1.2.3.4"
                          "1.2.3.4")))))