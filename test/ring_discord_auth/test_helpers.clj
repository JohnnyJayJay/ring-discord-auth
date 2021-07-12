(ns ring-discord-auth.test-helpers
  (:require [clojure.string :as str])
  (:import (java.security SecureRandom)
           (org.bouncycastle.crypto.generators Ed25519KeyPairGenerator)
           (org.bouncycastle.crypto.params Ed25519KeyGenerationParameters Ed25519PrivateKeyParameters Ed25519PublicKeyParameters)
           (org.bouncycastle.crypto.signers Ed25519Signer)))

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
