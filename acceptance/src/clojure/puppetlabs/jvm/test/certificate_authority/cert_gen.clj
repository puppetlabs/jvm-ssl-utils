(ns puppetlabs.jvm.test.certificate-authority.cert-gen
  (:import  [puppetlabs.jvm.test.certificate_authority PuppetMasterCertManager])
  (:require [puppetlabs.jvm.test.certificate-authority.puppet-agent-cert-manager :as client-ca]
            [me.raynes.fs :as fs]))

(defn generate
  []
  (-> (PuppetMasterCertManager. "acceptance/resources/server/conf" "localhost")
      (client-ca/initialize! "acceptance/resources/client/conf" "local-client")))

(defn clean
  []
  (fs/delete-dir "acceptance/resources/server")
  (fs/delete-dir "acceptance/resources/client"))

(defn -main
  "Create and destroy SSL certificates necessary for testing.

  Operations:

    `generate`  Create new SSL certificates

    `clean`     Remove everything created by `generate`"
  [& args]
  (condp = (first args)
    "generate" (generate)
    "clean"    (clean)))
