(ns puppetlabs.certificate-authority.test.server
  (:require [puppetlabs.trapperkeeper.core :as tk]
            [clojure.tools.logging :as log]))

(defn log-ssl-information
  [get-in-config]
  (doseq [setting [:ssl-host :ssl-port :ssl-cert :ssl-key :ssl-ca-cert]]
    (let [name  (name setting)
          value (get-in-config [:webserver setting])]
      (log/info (format "Test server initialized with: %s = %s" name value)))))

(tk/defservice secure-test-server
  [[:WebserverService add-ring-handler]
   [:ConfigService get-in-config]]
  (init [_ context]
        (log-ssl-information get-in-config)
        (add-ring-handler (fn [req] {:status 200 :body "Access granted"})
                          "/test-ssl")
        context)
  (stop [_ context]
        context))
