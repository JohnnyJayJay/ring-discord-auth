# ring-discord-auth

`ring-discord-auth` provides functions to verify ED-25519 signatures sent by Discord when using [webhook-based interactions](https://discord.com/developers/docs/interactions/slash-commands#receiving-an-interaction).

This does not provide support for Discord's OAuth2.

## Installation

This library uses [caesium](https://github.com/lvh/caesium), a cryptography library for Clojure. This library requires the presence of [libsodium](https://doc.libsodium.org/) version 1.0.18 or higher, a native library, so make sure to install that in your compilation/execution environment.

Quick ways to install libsodium:
- on Debian-based distros: `sudo apt update && sudo apt install libsodium-dev`
- on Arch-based distros: `pacman -S libsodium`
- on other Linux distros: it's probably also in your package manager

Check the libsodium site for [official installation info](https://doc.libsodium.org/installation) and other systems like Windows.

Then, you can add the library through the dependency below.

[![Clojars Project](https://img.shields.io/clojars/v/com.github.johnnyjayjay/ring-discord-auth.svg)](https://clojars.org/com.github.johnnyjayjay/ring-discord-auth)

## Usage

Below is an example of a minimal Discord app that uses the library. Here, a synchronous handler is used, but the middleware also supports asynchronous handlers.

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
terms of the MIT License which is available at
https://mit-license.org/.
