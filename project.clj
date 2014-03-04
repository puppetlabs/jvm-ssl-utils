(defproject certificate-authority "0.1.0-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-certificate-authority"
  :dependencies [[org.clojure/tools.logging "0.2.6"]
                 [org.bouncycastle/bcpkix-jdk15on "1.50"]
                 [clj-time "0.5.1"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :profiles {:dev {:dependencies [[org.clojure/clojure "1.5.1"]]
                   :resource-paths ["test-resources"]}
             :acceptance {:dependencies [[puppetlabs/trapperkeeper "0.3.2"]
                                         [puppetlabs/trapperkeeper-webserver-jetty7 "0.3.2"]
                                         [me.raynes/fs "1.4.3"]]
                          :main puppetlabs.trapperkeeper.main
                          :source-paths ["acceptance/src/clojure"]
                          :java-source-paths ["acceptance/src/java"]
                          :aliases {"server" ["trampoline" "run"
                                              "--config" "acceptance/resources/config.ini"
                                              "--bootstrap-config" "acceptance/resources/bootstrap.cfg"]

                                    "generate" ["run" "-m" "puppetlabs.jvm.test.certificate-authority.cert-gen" "generate"]

                                    "clean" ["run" "-m" "puppetlabs.jvm.test.certificate-authority.cert-gen" "clean"]}}})
