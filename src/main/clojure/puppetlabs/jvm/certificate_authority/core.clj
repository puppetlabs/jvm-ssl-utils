(ns puppetlabs.jvm.certificate-authority.core
  (:import [puppetlabs.jvm.certificate_authority.ssl PuppetMasterCertManager]))

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

(defn sign-certificate-request-stream!
  [manager certname request-stream]
  (.signCertificateRequestStream manager certname request-stream))

(defn certificate-revocation-list-stream
  [manager]
  (.getCRLStream manager))
