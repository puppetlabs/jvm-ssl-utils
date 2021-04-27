(defn deploy-info
  [url]
  { :url url
    :username :env/clojars_jenkins_username
    :password :env/clojars_jenkins_password
    :sign-releases false})

(defproject puppetlabs/ssl-utils "3.1.1-SNAPSHOT"
  :url "http://www.github.com/puppetlabs/jvm-ssl-utils"

  :description "SSL certificate management on the JVM."

  :min-lein-version "2.9.1"

  :parent-project {:coords [puppetlabs/clj-parent "4.6.20"]
                   :inherit [:managed-dependencies]}

  ;; Abort when version ranges or version conflicts are detected in
  ;; dependencies. Also supports :warn to simply emit warnings.
  :pedantic? :abort

  :dependencies [[org.clojure/clojure]
                 [org.clojure/tools.logging]
                 [commons-codec]
                 [clj-commons/fs]
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

  :profiles {:dev {:dependencies [[org.bouncycastle/bcpkix-jdk15on]]
                   :resource-paths ["test-resources"]}

             ;; per https://github.com/technomancy/leiningen/issues/1907
             ;; the provided profile is necessary for lein jar / lein install
             :provided {:dependencies [[org.bouncycastle/bcpkix-jdk15on]]
                        :resource-paths ["test-resources"]}

             :fips {:dependencies [[org.bouncycastle/bctls-fips]
                                   [org.bouncycastle/bcpkix-fips]
                                   [org.bouncycastle/bc-fips]]
                    ;; this only ensures that we run with the proper profiles
                    ;; during testing. This JVM opt will be set in the puppet module
                    ;; that sets up the JVM classpaths during installation.
                    :jvm-opts ~(let [version (System/getProperty "java.version")
                                     [major minor _] (clojure.string/split version #"\.")
                                     unsupported-ex (ex-info "Unsupported major Java version. Expects 8 or 11."
                                                      {:major major
                                                       :minor minor})]
                                 (condp = (java.lang.Integer/parseInt major)
                                   1 (if (= 8 (java.lang.Integer/parseInt minor))
                                       ["-Djava.security.properties==jdk8-fips-security"]
                                       (throw unsupported-ex))
                                   11 ["-Djava.security.properties==jdk11-fips-security"]
                                   (throw unsupported-ex)))
                    :resource-paths ["test-resources"]}

             :sources-jar {:java-source-paths ^:replace []
                           :jar-exclusions ^:replace []
                           :source-paths ^:replace ["src/clojure" "src/java"]}}

  :plugins [[lein-parent "0.3.7"]
            [puppetlabs/i18n "0.8.0"]]
  :lein-release {:scm         :git
                 :deploy-via  :lein-deploy}
  :deploy-repositories [["releases" ~(deploy-info "https://clojars.org/repo")]
                        ["snapshots" ~(deploy-info "https://clojars.org/repo")]]

  :repositories [["puppet-releases" "https://artifactory.delivery.puppetlabs.net/artifactory/list/clojure-releases__local/"]
                 ["puppet-snapshots" "https://artifactory.delivery.puppetlabs.net/artifactory/list/clojure-snapshots__local/"]])

