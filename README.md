# ring-discord-auth

`ring-discord-auth` provides functions to verify ED-25519 signatures sent by Discord when using [webhook-based interactions](https://discord.com/developers/docs/interactions/slash-commands#receiving-an-interaction).

This does not provide support for Discord's OAuth2.

## Installation

Then, you can add the library through the dependency below.

[![Clojars Project](https://img.shields.io/clojars/v/com.github.johnnyjayjay/ring-discord-auth.svg)](https://clojars.org/com.github.johnnyjayjay/ring-discord-auth)

## Usage

Below is an example of a minimal Discord app that uses the library. Here, a synchronous handler is used, but the middleware also supports asynchronous handlers.

``` clojure
(ns example.core
  (:gen-class)
  (:require [ring-discord-auth.ring :refer [wrap-authenticate]]
            [ring.middleware.json :refer [wrap-json-body wrap-json-response]]
            [ring.util.response :refer [response]]
            [org.http-kit.server :as http]))

(defn handler [{{:keys [type]} :body :as _request}]
  (response
   (case type
     1 {:type 1} ; Respond to PING with PONG
     2 {:type 4 :data {:content "Hello!"}} ; Respond to a slash command with "Hello!"
     3 {:type 6}))) ; ACK component presses but do nothing further

(def public-key "Your app's public key (can be found in the developer portal)")

(defn -main [& args]
  (http/run-server
   (-> handler
       wrap-json-response
       (wrap-json-body {:keywords? true})
       (wrap-authenticate public-key))))
```

Note that `wrap-authenticate` requires access to the raw, unmodified body and must therefore be run before `wrap-json-body`.

Or you can use the `ring-discord-auth.core/authentic?` directly.

```clojure
(ns example.core
  (:gen-class)
  (:require [ring-discord-auth.core :as discord-auth]))

(defn -main [& args]
  (let [public-key-hex "e421dceefff3a9d008b7898fcc0974813201800419d72f36d51e010d6a0acb71"
        timestamp "1625603592"
        body "this should be a json."
        signature "f31a129c4e06d93e195ea019392fc568fa7d63c9b43beb436d75f6826d5e5d36270763ee438f13ad5686ed310e8fa3253426af798927bf69cee2ff21be589109"]
    (discord-auth/authentic? signature body timestamp public-key-hex "utf8")))

;=> true
```

## License

Copyright © 2021 JohnnyJayJay, RafaelDelboni

This program and the accompanying materials are made available under the
terms of the MIT License which is available at
https://mit-license.org/.
