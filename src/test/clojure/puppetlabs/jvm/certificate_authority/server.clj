(ns puppetlabs.jvm.certificate-authority.server
  (:require [puppetlabs.trapperkeeper.core :refer [defservice]]))

(defservice secure-test-server
  {:depends  [[:webserver-service add-ring-handler]]
   :provides []}
  (-> (fn [req] {:status 200 :body "Access granted"})
      (add-ring-handler "/test-ssl"))
  {})
