(ns ring-discord-auth.ring
  "Core namespace containing functions to handle bytes, encodings and Discord authentication"
  (:require [ring-discord-auth.core :as core])
  (:import (java.io ByteArrayInputStream)))

(def signature-header "x-signature-ed25519")
(def timestamp-header "x-signature-timestamp")
(def default-charset "utf8")

(def default-headers {"Content-Type" "text/plain"
                      "Allow" "POST"})

(defn wrap-authenticate
  "Ring middleware to authenticate incoming requests according to the Discord specification.

  This means:
  - If request method is not POST, respond with status 405 (Method Not Allowed)
  - Get body from the request as well as [[signature-header]] and [[timestamp-header]] from the headers
  - If any of the above is not present, respond with status 400 (Bad Request)
  - Check the parameters for authenticity as defined by Discord
    - If authentic, delegate to the `handler` with a restored body
    - If not authentic, respond with status 401 (Unauthorized)

  The `public-key` is the public key of the corresponding Discord app. It may be given as a String or byte array.
  This middleware must be in the hierarchy **before** the body is processed.

  This middleware supports both synchronous and asynchronous handlers."
  [handler public-key]
  (let [public-key (cond-> public-key (string? public-key) core/hex->bytes)]
    (fn
      ([request respond raise]
       (let [validator (wrap-authenticate identity public-key)
             result (validator request)]
         (if (:status result)
           (respond result)
           (handler result respond raise))))
      ([{:keys [body character-encoding request-method]
         {signature signature-header timestamp timestamp-header} :headers
         :or {character-encoding default-charset}
         :as request}]
       (if (= request-method :post)
         (core/if-let-all [sig-bytes (some-> signature core/hex->bytes)
                                 time-bytes (some-> timestamp (core/encode character-encoding))
                                 body-bytes (some-> body core/read-all-bytes)]
           (if (core/authentic? sig-bytes body-bytes time-bytes public-key character-encoding)
             (handler (assoc request :body (ByteArrayInputStream. body-bytes)))
             {:status 401 :headers default-headers :body "Signature was not authentic."})
           {:status 400 :headers default-headers :body "Missing body, signature or timestamp."})
         {:status 405 :headers default-headers :body "Only POST requests are allowed"})))))
