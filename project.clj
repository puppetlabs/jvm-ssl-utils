(defproject jvm-certificate-authority "0.1.0-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-certificate-authority"
  :source-paths ["src/main"]
  :test-paths ["src/test"]
  :dependencies [[org.clojure/clojure "1.5.1"]]
  :profiles {:dev {:dependencies [[puppetlabs/trapperkeeper "0.1.0"]]
                   :main puppetlabs.trapperkeeper.main
                   :aliases {"server" ["trampoline" "run"
                                       "--config" "test-resources/config.ini"
                                       "--bootstrap-config" "test-resources/bootstrap.cfg"]}}})
