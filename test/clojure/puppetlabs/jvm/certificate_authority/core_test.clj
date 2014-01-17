(ns puppetlabs.jvm.certificate-authority.core-test
  (:require [clojure.test :refer :all]
            [me.raynes.fs :as fs]
            [puppetlabs.jvm.certificate-authority.core :as ca]))

(def confdir "test-resources/conf")

(use-fixtures :each
  (fn [test]
    (test)
    (fs/delete-dir confdir)))

;; TODO
;;  Replace these simple tests with meaningful ones
(deftest clojure-api
  (let [master-certname "localhost"
        manager         (ca/initialize! confdir master-certname)]

    (testing "initialize!"
      (is (not (nil? manager))))

    (testing "keystore"
      (is (not (nil? (ca/keystore manager)))))

    (testing "keystore-password"
      (is (= "puppet" (ca/keystore-password manager))))

    (testing "certificate-stream"
      (is (not (nil? (ca/certificate-stream manager master-certname)))))

    (testing "sign-certificate-request!"
      (is (thrown? NullPointerException (ca/sign-certificate-request! manager master-certname nil))))

    (testing "certificate-revocation-list-stream"
      (is (not (nil? (ca/certificate-revocation-list-stream manager)))))))
