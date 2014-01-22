(ns puppetlabs.jvm.certificate-authority.ssl.puppet-agent-cert-manager
  (:require [clojure.java.io :as io]
            [puppetlabs.jvm.certificate-authority.core :as ca])
  (:import (puppetlabs.jvm PathUtils)
           (org.apache.commons.io FileUtils)
           (puppetlabs.jvm.certificate_authority.ssl CertificateUtils)))

(defn- path-concat
  [& elements]
  (PathUtils/concat (first elements) (into-array String (rest elements))))

(defn- ssl-file-paths
  [ssldir certname]
  (let [pem-certname            (str certname ".pem")
        agent-public-key-path   (path-concat ssldir "public_keys" pem-certname)
        agent-private-key-path  (path-concat ssldir "private_keys" pem-certname)
        agent-cert-path         (path-concat ssldir "certs" pem-certname)]
    [agent-public-key-path agent-private-key-path agent-cert-path]))

(defn- already-initialized?
  [agent-ssl-paths]
  (every? #(-> %
               (io/file)
               (.exists))
          agent-ssl-paths))

(defn- create-directories!
  [agent-ssl-paths]
  (doseq [path agent-ssl-paths]
    (-> path
        (io/file)
        (.getParentFile)
        (FileUtils/forceMkdir))))

(defn- initialize-agent-cert!
  [agent-ssl-paths agent-certname master-ca]
  (create-directories! agent-ssl-paths)
  (let [agent-keypair     (CertificateUtils/generateKeyPair)
        agent-x500-name   (CertificateUtils/generateX500Name agent-certname)
        agent-cert-req    (CertificateUtils/generateCertReq agent-keypair agent-x500-name)
        agent-cert        (ca/sign-certificate-request! master-ca agent-certname agent-cert-req)]
    (CertificateUtils/saveToPEM (.getPublic agent-keypair) (nth agent-ssl-paths 0))
    (CertificateUtils/saveToPEM (.getPrivate agent-keypair) (nth agent-ssl-paths 1))
    (CertificateUtils/saveToPEM agent-cert (nth agent-ssl-paths 2))
    ;; HACK - assume the location of the ca.pem file and just directly copy it into place
    (FileUtils/copyFile (io/file "test-resources/server/conf/ssl/certs/ca.pem")
                        (io/file "test-resources/client/conf/ssl/certs/ca.pem"))))

(defn initialize!
  [master-ca confdir agent-certname]
  (let [ssldir          (path-concat confdir "ssl")
        agent-ssl-paths (ssl-file-paths ssldir agent-certname)]
    (when-not (already-initialized? agent-ssl-paths)
      (initialize-agent-cert! agent-ssl-paths agent-certname master-ca))))
