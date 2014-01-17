(ns puppetlabs.jvm.certificate-authority
  (:import [com.puppetlabs.jvm.ssl PuppetMasterCertManager]))

(defn initialize!
  [confdir master-certname]
  (PuppetMasterCertManager. confdir master-certname))

(defn keystore
  [manager]
  (.getKeystore manager))

(defn keystore-password
  [manager]
  (.getKeystorePassword manager))

(defn certificate-stream
  [manager certname]
  (.getCertStream manager certname))

(defn sign-certificate-request!
  [manager certname request]
  (.signCertificateRequest manager certname request))

(defn certificate-revocation-list-stream
  [manager]
  (.getCRLStream manager))
