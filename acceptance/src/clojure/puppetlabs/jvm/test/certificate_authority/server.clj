(ns puppetlabs.jvm.test.certificate-authority.server
  (:import [puppetlabs.jvm.test.certificate_authority PuppetMasterCertManager])
  (:require [puppetlabs.trapperkeeper.core :as tk]
            [puppetlabs.jvm.test.certificate-authority.puppet-agent-cert-manager :as client-ca]
            [me.raynes.fs :as fs]))

(defn cleanup
  []
  (fs/delete-dir "acceptance/resources/server")
  (fs/delete-dir "acceptance/resources/client"))

(tk/defservice secure-test-server
  [[:WebserverService add-ring-handler]]
  (init [_ context]
        (add-ring-handler (fn [req] {:status 200 :body "Access granted"})
                          "/test-ssl")
        context)
  (stop [_ context]
        (cleanup)
        context))

(defn -main
  [& args]
  (try
    (-> (PuppetMasterCertManager. "acceptance/resources/server/conf" "localhost")
        (client-ca/initialize! "acceptance/resources/client/conf" "local-client"))
    (apply tk/main args)
    (catch Exception e
      (cleanup)
      (throw e))))
