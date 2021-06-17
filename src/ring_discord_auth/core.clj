(ns ring-discord-auth.core
  "Core namespace containing functions to handle bytes, encodings and Discord authentication"
  (:require [clojure.java.io :as io]
            [caesium.crypto.sign :as sign]
            [clojure.test :refer [is]])
  (:import (java.nio.charset StandardCharsets Charset UnsupportedCharsetException IllegalCharsetNameException CharsetEncoder)
           (java.util Arrays)
           (java.nio ByteBuffer CharBuffer)
           (java.io ByteArrayOutputStream ByteArrayInputStream InputStream)))

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

(defmacro examples
  "Macro to generate illustrative tests for a function based on input-output pairs.

  `f` is the function to test.
  `equals` is the function used to compare the expected and actual result.
  Each example call is a sequence where the first n - 1 items are the inputs and the last item is the expected output."
  {:style/indent 1}
  [f equals & example-calls]
  `(fn []
     ~@(for [call example-calls
             :let [in (drop-last call)
                   out (last call)
                   out-ev (eval out)]]
         `(is (~equals (~f ~@in) ~out)))))

(defn hex->bytes
  "Converts the given string representing a hexadecimal number to a byte array.

  Each byte in the resulting array comes from 2 digits in the string.
  If the string cannot be converted, returns `nil`"
  {:test (examples hex->bytes Arrays/equals
           ["68c252fa74eb9b97" #_=> (byte-array [0x68 0xc2 0x52 0xfa 0x74 0xeb 0x9b 0x97])]
           ["123" #_=> (byte-array [0x12 0x03])]
           ["garbage" #_=> nil])}
  ^bytes [^String hex-str]
  (let [len (count hex-str)

        result (byte-array (quot (inc len) 2))]
    (try
      (doseq [[i hex-part] (map-indexed vector (map (partial apply str) (partition-all 2 hex-str)))]
        (aset result i (unchecked-byte (Short/parseShort hex-part 16))))
      result
      (catch NumberFormatException _ nil))))

(defn read-all-bytes
  "Reads all bytes from either an `InputStream` or a `ByteBuffer`.

  If an `InputStream` is provided, it will be consumed, but not closed.
  Returns its result as a *new* byte array."
  {:test (examples read-all-bytes Arrays/equals
           [(ByteBuffer/allocate 0) #_=> (byte-array 0)]
           [(io/input-stream (byte-array [0x12 0xab 0x4f])) #_=> (byte-array [0x12 0xab 0x4f])]
           [(ByteBuffer/wrap (byte-array [0x67 0x2a 0x4b 0x23 0x5c]) 1 2) #_=> (byte-array [0x2a 0x4b])])}
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

(defn encode
  "Encodes the given string to a byte array using the given charset/encoding.

  Returns `nil` if the charset is not available or if it doesn't support encoding."
  {:test (examples encode Arrays/equals
           ["Hello, world!", "utf8" #_=> (byte-array [0x48 0x65 0x6c 0x6c 0x6f 0x2c 0x20 0x77 0x6f 0x72 0x6c 0x64 0x21])]
           ["Another one", "unknown?" #_=> nil])}
  ^bytes [^String str ^String charset-name]
  (if-let-all [^Charset cs (try (Charset/forName charset-name) (catch UnsupportedCharsetException _ nil) (catch IllegalCharsetNameException _ nil))
               ^CharsetEncoder encoder (try (.newEncoder cs) (catch UnsupportedOperationException _ nil))]
    (when (.canEncode encoder str)
      (read-all-bytes (.encode encoder (CharBuffer/wrap str))))))

(defn authentic?
  "Checks whether a signature is authentic, given a message and a public key.

  This function has 2 arities: a general purpose one that simply delegates to a crypto library and one tailored to what Discord provides.

  The general purpose arity takes a signature, a message and a public key (all of which must be byte arrays) and checks the authenticity.

  The other arity takes a signature (byte array or hex string), public key (byte array or hex string), body (byte array or string), timestamp (byte array or string).
  It combines timestamp and body and uses that as the message.

  Returns `true` if the message is authentic, `false` if not."
  ([signature-bytes message-bytes public-key-bytes]
   (try
     (sign/verify signature-bytes message-bytes public-key-bytes)
     true
     (catch RuntimeException _ false)))
  ([signature body timestamp public-key charset-name]
   (if-let-all [signature-bytes (cond-> signature (not (bytes? signature)) hex->bytes)
                public-key-bytes (cond-> public-key (not (bytes? public-key)) hex->bytes)
                ^bytes body-bytes (cond-> body (string? body) (encode body charset-name))
                ^bytes timestamp-bytes (cond-> timestamp (string? timestamp) (encode timestamp charset-name))
                message-bytes (byte-array (+ (alength timestamp-bytes) (alength body-bytes)))]
     (do
       (System/arraycopy timestamp-bytes 0 message-bytes 0 (alength timestamp-bytes))
       (System/arraycopy body-bytes 0 message-bytes (alength timestamp-bytes) (alength body-bytes))
       (authentic? signature-bytes message-bytes public-key-bytes))
     false)))

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
  (let [public-key (cond-> public-key (string? public-key) hex->bytes)]
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
         (if-let-all [sig-bytes (some-> signature hex->bytes)
                      time-bytes (some-> timestamp (encode character-encoding))
                      body-bytes (some-> body read-all-bytes)]
           (if (authentic? sig-bytes body-bytes time-bytes public-key character-encoding)
             (handler (assoc request :body (ByteArrayInputStream. body-bytes)))
             {:status 401 :headers default-headers :body "Signature was not authentic."})
           {:status 400 :headers default-headers :body "Missing body, signature or timestamp."})
         {:status 405 :headers default-headers :body "Only POST requests are allowed"})))))
