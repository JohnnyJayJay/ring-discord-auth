(ns ring-discord-auth.validation
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [is]])
  (:import (java.io ByteArrayOutputStream InputStream)
           (java.nio ByteBuffer CharBuffer)
           (java.nio.charset Charset UnsupportedCharsetException IllegalCharsetNameException CharsetEncoder)
           (java.security SecureRandom)
           (java.util Arrays)
           (org.bouncycastle.crypto.generators Ed25519KeyPairGenerator)
           (org.bouncycastle.crypto.params Ed25519KeyGenerationParameters Ed25519PrivateKeyParameters Ed25519PublicKeyParameters)
           (org.bouncycastle.crypto.signers Ed25519Signer)))

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

(defn hex->bytes
  "Converts the given string representing a hexadecimal number to a byte array.
  Each byte in the resulting array comes from 2 digits in the string.

  If the string cannot be converted, returns `nil`"
  ^bytes [^String hex-str]
  (let [len (count hex-str)
        result (byte-array (quot (inc len) 2))]
    (try
      (doseq [[i hex-part] (map-indexed vector (map (partial apply str) (partition-all 2 hex-str)))]
        (aset result i (unchecked-byte (Short/parseShort hex-part 16))))
      result
      (catch NumberFormatException _ nil))))

(defn bytes->hex
  "Convert byte array to hex string."
  [^bytes byte-array]
  (let [hex [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \a \b \c \d \e \f]]
    (letfn [(hexify-byte [b]
              (let [v (bit-and b 0xFF)]
                [(hex (bit-shift-right v 4)) (hex (bit-and v 0x0F))]))]
      (str/join (mapcat hexify-byte byte-array)))))

(defn generate-keypair
  "Generate Ed25519 key pair.

  Return {:private `Ed25519PrivateKeyParameters`
          :public `Ed25519PublicKeyParameters`}"
  []
  (let [random (SecureRandom.)
        kpg    (Ed25519KeyPairGenerator.)
        _ (.init kpg (Ed25519KeyGenerationParameters. random))
        key-pair (.generateKeyPair kpg)]
    {:private (cast Ed25519PrivateKeyParameters (.getPrivate key-pair))
     :public  (cast Ed25519PublicKeyParameters (.getPublic key-pair))}))

(defn new-signer
  "Return new instance of `Ed25519Signer` initialized by private key"
  [private-key]
  (let [signer (Ed25519Signer.)]
    (.init signer true private-key)
    signer))

(defn sign
  "Generate signature for msg byte array.

  Return byte array with signature."
  [^Ed25519Signer signer msg-bytes]
  (.update signer msg-bytes 0 (alength msg-bytes))
  (.generateSignature signer))

(defn new-verifier
  "Return new instance of `Ed25519Signer` initialized by public key."
  [public-key]
  (let [signer (Ed25519Signer.)]
    (.init signer false public-key)
    signer))

(defn verify
  "Verify signature for msg byte array.

  Returns `true` if valid signature and `false` if not."
  [^Ed25519Signer signer msg-bytes signature]
  (.update signer msg-bytes 0 (alength msg-bytes))
  (.verifySignature signer signature))

(defn verify-request
  "Verify discord payload with app public-key, request body, signature and timestamp headers

  Returns `true` if the message is authentic, `false` if not."
  [public-key timestamp body signature]
  (verify (new-verifier (Ed25519PublicKeyParameters. (hex->bytes public-key) 0))
          (.getBytes (str timestamp body) "utf8")
          (hex->bytes signature)))

(defn authentic?
  "Checks whether a signature is authentic, given a message and a public key.

  This function has 2 arities: a general purpose one that simply delegates to a crypto library and one tailored to what Discord provides.

  The general purpose arity takes a signature, a message and a public key (all of which must be byte arrays) and checks the authenticity.
  The other arity takes a signature (byte array or hex string), public key (byte array or hex string), body (byte array or string), timestamp (byte array or string).

  It combines timestamp and body and uses that as the message.

  Returns `true` if the message is authentic, `false` if not."
  ([signature-bytes message-bytes public-key-bytes]
   (verify (new-verifier (Ed25519PublicKeyParameters. public-key-bytes 0))
            message-bytes
            signature-bytes))
  ([signature body timestamp public-key charset-name]
   (if-let-all [signature-bytes (cond-> signature (not (bytes? signature)) hex->bytes)
                public-key-bytes (cond-> public-key (not (bytes? public-key)) hex->bytes)
                ^bytes body-bytes (cond-> body (string? body) (encode charset-name))
                ^bytes timestamp-bytes (cond-> timestamp (string? timestamp) (encode charset-name))
                message-bytes (byte-array (+ (alength timestamp-bytes) (alength body-bytes)))]
     (do
       (System/arraycopy timestamp-bytes 0 message-bytes 0 (alength timestamp-bytes))
       (System/arraycopy body-bytes 0 message-bytes (alength timestamp-bytes) (alength body-bytes))
       (authentic? signature-bytes message-bytes public-key-bytes))
     false)))
