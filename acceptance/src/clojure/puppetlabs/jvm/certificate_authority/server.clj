(ns puppetlabs.jvm.certificate-authority.server
  (:import [puppetlabs.jvm.certificate_authority.ssl PuppetMasterCertManager])
  (:require [puppetlabs.trapperkeeper.core :as tk]
            [puppetlabs.jvm.certificate-authority.ssl.puppet-agent-cert-manager :as client-ca]
            [me.raynes.fs :as fs]))

(defn cleanup
  []
  (fs/delete-dir "acceptance/resources/server")
  (fs/delete-dir "acceptance/resources/client"))

(tk/defservice secure-test-server
  {:depends  [[:webserver-service add-ring-handler]]
   :provides [shutdown]}
  (-> (fn [req] {:status 200 :body "Access granted"})
      (add-ring-handler "/test-ssl"))
   {:shutdown cleanup})

(defn -main
  [& args]
  (-> (PuppetMasterCertManager. "acceptance/resources/server/conf" "localhost")
      (client-ca/initialize! "acceptance/resources/client/conf" "local-client"))
  (apply tk/main args))
