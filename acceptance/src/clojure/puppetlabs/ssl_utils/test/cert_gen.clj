(ns puppetlabs.ssl-utils.test.cert-gen
  (:import  [com.puppetlabs.ssl_utils.test PuppetMasterCertManager])
  (:require [puppetlabs.ssl-utils.test.puppet-agent-cert-manager :as client-ca]
            [me.raynes.fs :as fs]
            [clojure.tools.logging :as log]))

(defn generate
  [{:keys [server-ssl-dir client-ssl-dir server-subject-name client-subject-name]}]
  (log/info (format "Generating server certificates at '%s' for '%s'" server-ssl-dir server-subject-name))
  (log/info (format "Generating client certificates at '%s' for '%s'" client-ssl-dir client-subject-name))
  (-> (PuppetMasterCertManager. server-ssl-dir server-subject-name)
      (client-ca/initialize! client-ssl-dir client-subject-name)))

(defn clean
  [{:keys [server-ssl-dir client-ssl-dir]}]
  (fs/delete-dir server-ssl-dir)
  (fs/delete-dir client-ssl-dir))

(defn -main
  "Create and destroy SSL certificates necessary for testing.

  Operations:

    `generate`  Create new SSL certificates

    `clean`     Remove everything created by `generate`"
  [& args]
  (let [client-server-ssl-info {:server-ssl-dir      "./acceptance/resources/server"
                                :client-ssl-dir      "./acceptance/resources/client"
                                :server-subject-name "localhost"
                                :client-subject-name "local-client"}]
    (condp = (first args)
      "generate" (generate client-server-ssl-info)
      "clean"    (clean client-server-ssl-info))))
