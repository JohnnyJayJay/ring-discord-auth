(ns ring-discord-auth.core
  "Core namespace containing functions to handle bytes, encodings and Discord authentication"
  (:require [ring-discord-auth.validation :as validation])
  (:import (java.io ByteArrayOutputStream ByteArrayInputStream InputStream)
           (java.nio ByteBuffer)))

(def signature-header "x-signature-ed25519")
(def timestamp-header "x-signature-timestamp")
(def default-headers {"Content-Type" "text/plain"
                      "Allow" "POST"})

(defmacro if-let-all
  "Utility-macro - like `if-let`, but with multiple bindings that are all tested."
  {:style/indent 1}
  ([bindings then]
   `(if-let-all ~bindings ~then nil))
  ([bindings then else]
   (assert (vector? bindings))
   (let [amount (count bindings)]
     (assert (= (rem amount 2) 0))
     (assert (>= amount 2))
     `(if-let [~(first bindings) ~(second bindings)]
        ~(if (> amount 2)
           `(if-let-all ~(subvec bindings 2) ~then ~else)
           then)
        ~else))))

(defn read-all-bytes
  "Reads all bytes from either an `InputStream` or a `ByteBuffer`.
  If an `InputStream` is provided, it will be consumed, but not closed.
  Returns its result as a *new* byte array."
  ^bytes [input]
  (condp instance? input
    InputStream (let [bos (ByteArrayOutputStream.)]
                  (loop [next (.read ^InputStream input)]
                    (if (== next -1)
                      (.toByteArray bos)
                      (do
                        (.write bos next)
                        (recur (.read ^InputStream input))))))
    ByteBuffer (let [len (.remaining ^ByteBuffer input)
                     result (byte-array len)]
                 (.get ^ByteBuffer input result)
                 result)))

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
  (fn
    ([request respond raise]
     (let [validator (wrap-authenticate identity public-key)
           result (validator request)]
       (if (:status result)
         (respond result)
         (handler result respond raise))))
    ([{:keys [body request-method]
       {signature signature-header timestamp timestamp-header} :headers
       :as request}]
     (if (= request-method :post)
       (if-let-all [public-key-hex public-key
                    raw-body (read-all-bytes body)
                    timestamp-hex timestamp
                    signature-hex signature
                    body (slurp raw-body)]
                   (if (validation/verify-request public-key-hex timestamp-hex body signature-hex)
                     (handler (assoc request :body (ByteArrayInputStream. raw-body)))
                     {:status 401 :headers default-headers :body "Signature was not authentic."})
                   {:status 400 :headers default-headers :body "Missing body, signature or timestamp."})
       {:status 405 :headers default-headers :body "Only POST requests are allowed"}))))
