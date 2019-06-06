(defn deploy-info
  [url]
  { :url url
    :username :env/clojars_jenkins_username
    :password :env/clojars_jenkins_password
    :sign-releases false })

(defproject puppetlabs/ssl-utils "2.0.1-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-ssl-utils"

  :description "SSL certificate management on the JVM."

  :min-lein-version "2.7.1"

  :parent-project {:coords [puppetlabs/clj-parent "3.0.0"]
                   :inherit [:managed-dependencies]}

  ;; Abort when version ranges or version conflicts are detected in
  ;; dependencies. Also supports :warn to simply emit warnings.
  :pedantic? :abort

  :dependencies [[org.clojure/tools.logging]
                 [commons-codec]
                 [clj-time]
                 [puppetlabs/i18n]
                 [prismatic/schema]]

  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :jar-exclusions [#".*\.java$"]

  ;; By declaring a classifier here and a corresponding profile below we'll get an additional jar
  ;; during `lein jar` that has all the source code (including the java source). Downstream projects can then
  ;; depend on this source jar using a :classifier in their :dependencies.
  :classifiers [["sources" :sources-jar]]

  :profiles {:dev {:dependencies [[org.clojure/clojure]
                                  [org.bouncycastle/bcpkix-jdk15on]]
                   :resource-paths ["test-resources"]}

             ;; per https://github.com/technomancy/leiningen/issues/1907
             ;; the provided profile is necessary for lein jar / lein install
             :provided {:dependencies [[org.bouncycastle/bcpkix-jdk15on]]
                        :resource-paths ["test-resources"]}

             :fips {:dependencies [[org.clojure/clojure]
                                   [org.bouncycastle/bcpkix-fips]
                                   [org.bouncycastle/bc-fips]]
                   :resource-paths ["test-resources"]}

             :sources-jar {:java-source-paths ^:replace []
                           :jar-exclusions ^:replace []
                           :source-paths ^:replace ["src/clojure" "src/java"]}}

  :plugins [[lein-parent "0.3.5"]
            [puppetlabs/i18n "0.8.0"]]
  :lein-release {:scm         :git
                 :deploy-via  :lein-deploy}
  :deploy-repositories [["releases" ~(deploy-info "https://clojars.org/repo")]
                        ["snapshots" ~(deploy-info "https://clojars.org/repo")]]

  :repositories [["puppet-releases" "https://artifactory.delivery.puppetlabs.net/artifactory/list/clojure-releases__local/"]
                 ["puppet-snapshots" "https://artifactory.delivery.puppetlabs.net/artifactory/list/clojure-snapshots__local/"]])
