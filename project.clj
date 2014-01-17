(defproject jvm-certificate-authority "0.1.0-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-certificate-authority"
  :dependencies [[org.clojure/clojure "1.5.1"]]
  :source-paths ["src/main/clojure"]
  :test-paths ["test/clojure"]
  :java-source-paths ["src/main/java"]
  :profiles {:dev {:dependencies [[puppetlabs/trapperkeeper "0.1.0"] [me.raynes/fs "1.4.3"]]
                   :main puppetlabs.jvm.certificate-authority.server
                   :source-paths ["src/main/clojure" "src/test/clojure"]
                   :aliases {"server" ["trampoline" "run"
                                       "--config" "test-resources/config.ini"
                                       "--bootstrap-config" "test-resources/bootstrap.cfg"]}}})
