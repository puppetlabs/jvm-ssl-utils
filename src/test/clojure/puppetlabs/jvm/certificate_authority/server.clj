(ns puppetlabs.jvm.certificate-authority.server
  (:require [puppetlabs.trapperkeeper.core :as tk]
            [puppetlabs.jvm.certificate-authority.core :as server-ca]
            [puppetlabs.jvm.certificate-authority.ssl.puppet-agent-cert-manager :as client-ca]
            [me.raynes.fs :as fs]))

(defn cleanup
  []
  (fs/delete-dir "test-resources/server")
  (fs/delete-dir "test-resources/client"))

(tk/defservice secure-test-server
  {:depends  [[:webserver-service add-ring-handler]]
   :provides [shutdown]}
  (-> (fn [req] {:status 200 :body "Access granted"})
      (add-ring-handler "/test-ssl"))
   {:shutdown cleanup})

(defn -main
  [& args]
  (-> (server-ca/initialize! "test-resources/server/conf" "localhost")
      (client-ca/initialize! "test-resources/client/conf" "local-client"))
  (apply tk/main args))
