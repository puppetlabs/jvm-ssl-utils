(ns puppetlabs.jvm.test.certificate-authority.puppet-agent-cert-manager
  (:require [clojure.java.io :as io]
            [me.raynes.fs :as fs])
  (:import (puppetlabs.jvm.test PathUtils)
           (puppetlabs.jvm.test.certificate_authority PuppetMasterCertManager)
           (puppetlabs.jvm.certificate_authority CertificateAuthority)))

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
        (fs/mkdirs))))

(defn- initialize-agent-cert!
  [agent-ssl-paths agent-certname master-ca]
  (create-directories! agent-ssl-paths)
  (let [agent-keypair     (CertificateAuthority/generateKeyPair)
        agent-x500-name   (CertificateAuthority/generateX500Name agent-certname)
        agent-cert-req    (CertificateAuthority/generateCertificateRequest agent-keypair agent-x500-name)
        agent-cert        (.signCertificateRequest master-ca agent-certname agent-cert-req)]
    (CertificateAuthority/writeToPEM (.getPublic agent-keypair) (io/writer (nth agent-ssl-paths 0)))
    (CertificateAuthority/writeToPEM (.getPrivate agent-keypair) (io/writer (nth agent-ssl-paths 1)))
    (CertificateAuthority/writeToPEM agent-cert (io/writer (nth agent-ssl-paths 2)))
    ;; HACK - assume the location of the ca.pem file and just directly copy it into place
    (fs/copy (io/file "acceptance/resources/server/conf/ssl/certs/ca.pem")
             (io/file "acceptance/resources/client/conf/ssl/certs/ca.pem"))))

(defn initialize!
  [master-ca confdir agent-certname]
  (let [ssldir          (path-concat confdir "ssl")
        agent-ssl-paths (ssl-file-paths ssldir agent-certname)]
    (when-not (already-initialized? agent-ssl-paths)
      (initialize-agent-cert! agent-ssl-paths agent-certname master-ca))))
