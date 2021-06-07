(defproject com.github.johnnyjayjay/ring-discord-auth "0.1.0-SNAPSHOT"
  :description "Fast and secure ring middleware to verify ED-25519-signed Discord interactions"
  :url "https://github.com/JohnnyJayJay/ring-discord-auth"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [caesium "0.14.0"]]
  :global-vars {*warn-on-reflection* true}
  :repl-options {:init-ns ring-discord-auth.core})
