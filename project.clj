(defproject jvm-certificate-authority "0.1.0-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-certificate-authority"
  :dependencies [[org.clojure/clojure "1.5.1"]]
  :java-source-paths ["src/main/java"]
  :profiles {:acceptance {:dependencies [[puppetlabs/trapperkeeper "0.1.0"] [me.raynes/fs "1.4.3"]]
                          :main puppetlabs.jvm.certificate-authority.server
                          :source-paths ["acceptance/src/clojure"]
                          :java-source-paths ["acceptance/src/java"]
                          :aliases {"server" ["trampoline" "run"
                                              "--config" "acceptance/resources/config.ini"
                                              "--bootstrap-config" "acceptance/resources/bootstrap.cfg"]}}})
