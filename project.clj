(defproject jvm-certificate-authority "0.1.0-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-certificate-authority"
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [org.clojure/tools.logging "0.2.6"]
                 [org.bouncycastle/bcpkix-jdk15on "1.49"]
                 [clj-time "0.5.1"]]
  :source-paths ["src/main/clojure"]
  :java-source-paths ["src/main/java"]
  :profiles {:dev {:resource-paths ["test-resources"]}
             :test {:resource-paths ["test-resources"]}
             :acceptance {:dependencies [[puppetlabs/trapperkeeper "0.3.2"]
                                         [puppetlabs/trapperkeeper-webserver-jetty7 "0.3.2"]
                                         [me.raynes/fs "1.4.3"]]
                          :main puppetlabs.jvm.certificate-authority.server
                          :source-paths ["acceptance/src/clojure"]
                          :java-source-paths ["acceptance/src/java"]
                          :aliases {"server" ["trampoline" "run"
                                              "--config" "acceptance/resources/config.ini"
                                              "--bootstrap-config" "acceptance/resources/bootstrap.cfg"]}}})
