(defproject com.github.johnnyjayjay/ring-discord-auth "1.0.1"
  :description "Fast and secure functions and ring middleware to verify ED-25519-signed Discord interactions"
  :url "https://github.com/JohnnyJayJay/ring-discord-auth"
  :license {:name "MIT License"
            :url "https://mit-license.org/"}
  :repositories [["releases" {:url "https://clojars.org"
                              :creds :gpg}]]
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [org.bouncycastle/bcprov-jdk15on "1.69"]]
  :global-vars {*warn-on-reflection* true}
  :repl-options {:init-ns ring-discord-auth.core})
