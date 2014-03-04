(ns puppetlabs.jvm.test.certificate-authority.server
  (:require [puppetlabs.trapperkeeper.core :as tk]))

(tk/defservice secure-test-server
  [[:WebserverService add-ring-handler]]
  (init [_ context]
        (add-ring-handler (fn [req] {:status 200 :body "Access granted"})
                          "/test-ssl")
        context)
  (stop [_ context]
        context))
