(defn deploy-info
  [url]
  { :url url
    :username :env/clojars_jenkins_username
    :password :env/clojars_jenkins_password
    :sign-releases false })

(defproject puppetlabs/certificate-authority "0.3.2-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-certificate-authority"

  ;; Abort when version ranges or version conflicts are detected in
  ;; dependencies. Also supports :warn to simply emit warnings.
  ;; requires lein 2.2.0+.
  :pedantic? :abort

  :dependencies [[org.clojure/tools.logging "0.2.6" :exclusions [org.clojure/clojure]]
                 [org.bouncycastle/bcpkix-jdk15on "1.50"]
                 [clj-time "0.5.1"]]

  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :jar-exclusions [#".*\.java$"]
  :javac-options ["-target" "1.6" "-source" "1.6" "-Xlint:-options"]

  ;; By declaring a classifier here and a corresponding profile below we'll get an additional jar
  ;; during `lein jar` that has all the source code (including the java source). Downstream projects can then
  ;; depend on this source jar using a :classifier in their :dependencies.
  :classifiers [["sources" :sources-jar]]

  :profiles {:dev {:dependencies [[org.clojure/clojure "1.5.1"]]
                   :resource-paths ["test-resources"]}

             :sources-jar {:java-source-paths ^:replace []
                           :jar-exclusions ^:replace []
                           :source-paths ^:replace ["src/clojure" "src/java"]}

             :acceptance {:dependencies [[puppetlabs/trapperkeeper "0.3.2"]
                                         [puppetlabs/trapperkeeper-webserver-jetty7 "0.3.2"]
                                         [me.raynes/fs "1.4.3"]]
                          :main puppetlabs.trapperkeeper.main
                          :source-paths ["acceptance/src/clojure"]
                          :java-source-paths ["acceptance/src/java"]
                          :aliases {"server" ["trampoline" "run"
                                              "--config" "acceptance/resources/config.ini"
                                              "--bootstrap-config" "acceptance/resources/bootstrap.cfg"]

                                    "generate" ["run" "-m" "puppetlabs.certificate-authority.test.cert-gen" "generate"]

                                    "clean" ["run" "-m" "puppetlabs.certificate-authority.test.cert-gen" "clean"]}}}
  :plugins [[lein-release "1.0.5"]]
  :lein-release {:scm         :git
                 :deploy-via  :lein-deploy}
  :deploy-repositories [["releases" ~(deploy-info "https://clojars.org/repo")]
                        ["snapshots" ~(deploy-info "https://clojars.org/repo")]]

  )
