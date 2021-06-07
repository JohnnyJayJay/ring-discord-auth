# ring-discord-auth

`ring-discord-auth` provides functions to verify ED-25519 signatures sent by Discord when using [webhook-based interactions](https://discord.com/developers/docs/interactions/slash-commands#receiving-an-interaction).

This does not provide support for Discord's OAuth2.

## Installation

This library uses [caesium](https://github.com/lvh/caesium), a cryptography library for Clojure. This library requires the presence of [libsodium](https://doc.libsodium.org/), a native library, so make sure to install that.

[![Clojars Project](https://img.shields.io/clojars/v/com.github.johnnyjayjay/ring-discord-auth.svg)](https://clojars.org/com.github.johnnyjayjay/ring-discord-auth)

## Usage

Below is an example of a minimal Discord app that uses the library.

``` clojure
(ns example.core
  (:gen-class)
  (:require [ring-discord-auth.core :refer [wrap-authenticate]]
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

## License

Copyright © 2021 JohnnyJayJay

This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0.

This Source Code may also be made available under the following Secondary
Licenses when the conditions for such availability set forth in the Eclipse
Public License, v. 2.0 are satisfied: GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or (at your
option) any later version, with the GNU Classpath Exception which is available
at https://www.gnu.org/software/classpath/license.html.
