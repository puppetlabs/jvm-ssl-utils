(ns puppetlabs.jvm.certificate-authority.server
  (:require [puppetlabs.trapperkeeper.core :as tk]
            [puppetlabs.jvm.certificate-authority.core :as ca]
            [me.raynes.fs :as fs]))

(def confdir "test-resources/conf")

(tk/defservice secure-test-server
  {:depends  [[:webserver-service add-ring-handler]]
   :provides [shutdown]}
  (-> (fn [req] {:status 200 :body "Access granted"})
      (add-ring-handler "/test-ssl"))
   {:shutdown #(fs/delete-dir confdir)})

(defn -main
  [& args]
  (ca/initialize! confdir "localhost")
  (apply tk/main args))
