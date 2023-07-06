(ns puppetlabs.ssl-utils.extensions-utils-test
  (:require [clojure.test :refer :all]
            [puppetlabs.ssl-utils.simple-test :as simple-test]
            [puppetlabs.ssl-utils.core :as ssl-utils]
            [puppetlabs.ssl-utils.simple :as simple])
  (:import (java.net InetAddress)))

(deftest general-names
  (testing "InetAddress.toString() returns proper string form."
    (let [addr (InetAddress/getByAddress (byte-array [192 168 2 1]))]
      (is (= "/192.168.2.1" (.toString addr)))))

  (testing "Can encode and decode all General Names types"
    (let [gns {:rfc822-name ["foo@bar.com"]
               :dns-name ["localhost.localdomain"]
               :uri ["file:///foo/bar"]
               :ip ["192.168.69.90"]
               :registered-id ["1.2.3.4"]}
          in-exts [{:oid ssl-utils/subject-alt-name-oid
                    :critical true
                    :value gns}]
          opts {:extensions in-exts
                :keylength 512}
          ssl-cert (simple/gen-self-signed-cert "test" 42 opts)
          cert (simple-test/roundtrip-pem
                 ssl-utils/cert->pem! ssl-utils/pem->cert (:cert ssl-cert))
          out-exts (ssl-utils/get-extensions cert)]
      (is (= in-exts out-exts)))))
