(defn deploy-info
  [url]
  { :url url
    :username :env/clojars_jenkins_username
    :password :env/clojars_jenkins_password
    :sign-releases false })

(defproject puppetlabs/ssl-utils "0.8.1"
  :url "http://www.github.com/puppetlabs/jvm-ssl-utils"

  :description "SSL certificate management on the JVM."

  ;; Abort when version ranges or version conflicts are detected in
  ;; dependencies. Also supports :warn to simply emit warnings.
  ;; requires lein 2.2.0+.
  :pedantic? :abort

  :dependencies [[org.clojure/tools.logging "0.2.6" :exclusions [org.clojure/clojure]]
                 [org.bouncycastle/bcpkix-jdk15on "1.50"]
                 [commons-codec "1.9"]
                 [clj-time "0.7.0"]]

  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :jar-exclusions [#".*\.java$"]

  ;; By declaring a classifier here and a corresponding profile below we'll get an additional jar
  ;; during `lein jar` that has all the source code (including the java source). Downstream projects can then
  ;; depend on this source jar using a :classifier in their :dependencies.
  :classifiers [["sources" :sources-jar]]

  :profiles {:dev {:dependencies [[org.clojure/clojure "1.6.0"]]
                   :resource-paths ["test-resources"]}

             :sources-jar {:java-source-paths ^:replace []
                           :jar-exclusions ^:replace []
                           :source-paths ^:replace ["src/clojure" "src/java"]}}

  :plugins [[lein-release "1.0.5"]]
  :lein-release {:scm         :git
                 :deploy-via  :lein-deploy}
  :deploy-repositories [["releases" ~(deploy-info "https://clojars.org/repo")]
                        ["snapshots" ~(deploy-info "https://clojars.org/repo")]]

  )
